import base64
import json
import os
import requests
import socket
import time
import yaml
import subprocess
import random
import string
import sys
import logging
import hashlib
from datetime import datetime
from urllib.parse import unquote, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# ==================== 全局配置 ====================
SUBSCRIPTION_URLS_FILE = 'sub_urls.txt'
OUTPUT_CLASH_FILE = 'sub.yaml'
UPDATE_TIME_FILE = 'update_time.txt'

# 二进制文件路径 (自动处理 Windows 扩展名)
IS_WIN = sys.platform.startswith('win')
V2RAY_BINARY = './v2ray.exe' if IS_WIN else './v2ray'
CLASH_BINARY = './clash.exe' if IS_WIN else './clash'

# 测试逻辑配置
STAGE1_V2RAY_TEST = True
STAGE1_TOP_N = 300
STAGE2_SCHOLAR_TEST = True

V2RAY_TEST_TIMEOUT = 12
V2RAY_TEST_URL = 'http://www.gstatic.com/generate_204'
MAX_LATENCY_MS = 1500
MAX_NODES_LIMIT = 50

# 并发控制
MAX_WORKERS_FETCH = 10
MAX_WORKERS_V2RAY = 12
MAX_WORKERS_CLASH = 4

# 学术验证
SCHOLAR_VERIFY_URL = 'https://scholar.google.com/scholar?q=test'
SCHOLAR_KEYWORDS = ['scholar', 'articles', 'cited by']

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# ==================== 工具函数 ====================
def random_string(length=6):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def node_hash(node):
    key = f"{node.get('type')}:{node.get('server')}:{node.get('port')}"
    return hashlib.md5(key.encode()).hexdigest()

def standardize_node(node):
    node.setdefault('udp', True)
    node.setdefault('skip-cert-verify', True)
    return node

# ==================== 订阅获取与解析 ====================
def get_subscription_content(url):
    headers = {'User-Agent': 'Clash/1.0.0'}
    try:
        response = requests.get(url, timeout=20, headers=headers)
        response.raise_for_status()
        return response.text
    except Exception as e:
        logger.error(f"无法获取订阅 {url[:40]}: {e}")
        return None

def decode_base64_content(content):
    try:
        content = content.replace('-', '+').replace('_', '/')
        padding = (4 - len(content) % 4) % 4
        return base64.b64decode(content + '=' * padding).decode('utf-8', errors='ignore')
    except:
        return None

def parse_vmess_link(link):
    try:
        data = json.loads(decode_base64_content(link[8:]))
        node = {
            'name': data.get('ps', 'vmess'),
            'type': 'vmess',
            'server': data['add'],
            'port': int(data['port']),
            'uuid': data['id'],
            'alterId': int(data.get('aid', 0)),
            'cipher': 'auto',
            'tls': data.get('tls') == 'tls',
            'network': data.get('net', 'tcp'),
            'ws-opts': {'path': data.get('path', '/'), 'headers': {'Host': data.get('host', '')}} if data.get('net') == 'ws' else None
        }
        return standardize_node(node)
    except:
        return None

def parse_vless_link(link):
    try:
        parts = urlparse(link)
        uuid = parts.netloc.split('@')[0]
        server_port = parts.netloc.split('@')[1]
        server, port = server_port.split(':')
        params = {k: v[0] for k, v in parse_qs(parts.query).items()}
        node = {
            'name': unquote(parts.fragment) if parts.fragment else f"vless_{server}",
            'type': 'vless',
            'server': server,
            'port': int(port),
            'uuid': uuid,
            'network': params.get('type', 'tcp'),
            'tls': params.get('security') in ['tls', 'xtls', 'reality'],
            'udp': True
        }
        return standardize_node(node)
    except:
        return None

def parse_all_nodes(all_contents):
    all_nodes = []
    unique_set = set()
    for content in all_contents.values():
        decoded = decode_base64_content(content) or content
        for line in decoded.splitlines():
            line = line.strip()
            node = None
            if line.startswith('vmess://'): node = parse_vmess_link(line)
            elif line.startswith('vless://'): node = parse_vless_link(line)
            # 简化版：这里可以继续添加其他协议解析器
            if node:
                h = node_hash(node)
                if h not in unique_set:
                    all_nodes.append(node)
                    unique_set.add(h)
    return all_nodes

# ==================== 阶段1: V2ray 快速测试 ====================
def generate_v2ray_config(node, socks_port, http_port):
    """修复版：增加了对 WS 和 TLS 配置的完整支持 [web:6]"""
    outbound = {"protocol": node['type'], "settings": {}}
    
    if node['type'] == 'vmess':
        outbound['settings'] = {"vnext": [{"address": node['server'], "port": node['port'], "users": [{"id": node['uuid'], "alterId": node['alterId']}]}]}
    elif node['type'] == 'vless':
        outbound['settings'] = {"vnext": [{"address": node['server'], "port": node['port'], "users": [{"id": node['uuid'], "encryption": "none"}]}]}

    stream_settings = {"network": node.get('network', 'tcp')}
    if node.get('tls'):
        stream_settings['security'] = 'tls'
        stream_settings['tlsSettings'] = {'allowInsecure': True}
    
    # 核心修复：添加 WebSocket 路径支持
    if node.get('network') == 'ws':
        ws_opts = node.get('ws-opts', {}) or {}
        stream_settings['wsSettings'] = {
            'path': ws_opts.get('path', '/'),
            'headers': ws_opts.get('headers', {})
        }
    
    outbound['streamSettings'] = stream_settings

    return {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": http_port, "protocol": "http", "settings": {"udp": True}}],
        "outbounds": [outbound]
    }

def test_node_with_v2ray(node):
    rid = random_string()
    conf_path = f'v_{rid}.json'
    hp = get_free_port()
    try:
        with open(conf_path, 'w') as f: json.dump(generate_v2ray_config(node, 0, hp), f)
        
        # 使用 run 指令兼容 V2ray V5 [web:6]
        proc = subprocess.Popen([V2RAY_BINARY, 'run', '-c', conf_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        
        start = time.time()
        res = requests.get(V2RAY_TEST_URL, proxies={'http': f'http://127.0.0.1:{hp}'}, timeout=V2RAY_TEST_TIMEOUT)
        if res.status_code < 400:
            return round((time.time() - start) * 1000)
    except: pass
    finally:
        try: proc.terminate()
        except: pass
        if os.path.exists(conf_path): os.remove(conf_path)
    return -1

def stage1_v2ray_test(nodes):
    logger.info(f"开始阶段1测试: {len(nodes)} 个节点")
    valid = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_V2RAY) as executor:
        futures = {executor.submit(test_node_with_v2ray, n): n for n in nodes}
        for f in tqdm(as_completed(futures), total=len(nodes), desc="延迟测试"):
            d = f.result()
            if 0 < d < MAX_LATENCY_MS:
                valid.append({'node': futures[f], 'delay': d})
    
    valid.sort(key=lambda x: x['delay'])
    return [x['node'] for x in valid[:STAGE1_TOP_N]]

# ==================== 阶段2: Clash Scholar 验证 ====================
def test_node_with_clash(node):
    rid = random_string()
    cp = f'c_{rid}.yaml'
    ap, sp = get_free_port(), get_free_port()
    
    # 生成极简 Clash 配置
    conf = {
        'proxies': [node],
        'external-controller': f'127.0.0.1:{ap}',
        'socks-port': sp,
        'log-level': 'silent',
        'mode': 'rule'
    }
    
    try:
        with open(cp, 'w', encoding='utf-8') as f: yaml.dump(conf, f)
        proc = subprocess.Popen([CLASH_BINARY, '-f', cp, '-d', '.'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # 等待 Clash 启动
        for _ in range(15):
            try:
                if requests.get(f'http://127.0.0.1:{ap}/version', timeout=0.5).status_code == 200: break
            except: pass
            time.sleep(0.5)
        
        # Scholar 验证 [web:7][web:13]
        proxies = {'https': f'socks5h://127.0.0.1:{sp}'}
        res = requests.get(SCHOLAR_VERIFY_URL, proxies=proxies, timeout=15, headers={'User-Agent': 'Mozilla/5.0'}, verify=False)
        
        if res.status_code == 200:
            content = res.text.lower()
            if any(kw in content for kw in SCHOLAR_KEYWORDS):
                logger.info(f"✓ 通过的节点: {node['name']}")
                return node
    except: pass
    finally:
        try: proc.terminate()
        except: pass
        if os.path.exists(cp): os.remove(cp)
    return None

def stage2_clash_test(nodes):
    logger.info(f"开始阶段2测试: {len(nodes)} 个节点")
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_CLASH) as executor:
        futures = [executor.submit(test_node_with_clash, n) for n in nodes]
        for f in tqdm(as_completed(futures), total=len(nodes), desc="学术验证"):
            res = f.result()
            if res:
                results.append(res)
                if len(results) >= MAX_NODES_LIMIT: break
    return results

# ==================== 主程序 ====================
def main():
    if not os.path.exists(V2RAY_BINARY) or not os.path.exists(CLASH_BINARY):
        logger.error("核心文件缺失！请确保 v2ray 和 clash 存在于当前目录。")
        return

    if not os.path.exists(SUBSCRIPTION_URLS_FILE):
        open(SUBSCRIPTION_URLS_FILE, 'w').write("# 在此放入订阅链接")
        return

    with open(SUBSCRIPTION_URLS_FILE, 'r') as f:
        urls = [l.strip() for l in f if l.strip() and not l.startswith('#')]

    # 1. 获取并解析
    contents = {url: get_subscription_content(url) for url in urls}
    contents = {k: v for k, v in contents.items() if v}
    all_nodes = parse_all_nodes(contents)
    logger.info(f"解析到 {len(all_nodes)} 个唯一节点")

    # 2. 阶段 1 测试
    stage1_nodes = stage1_v2ray_test(all_nodes) if STAGE1_V2RAY_TEST else all_nodes
    if not stage1_nodes:
        logger.warning("没有节点通过阶段 1 测试")
        return

    # 3. 阶段 2 测试
    final_nodes = stage2_clash_test(stage1_nodes) if STAGE2_SCHOLAR_TEST else stage1_nodes

    # 4. 生成配置
    if final_nodes:
        clash_final = {
            'proxies': final_nodes,
            'proxy-groups': [{'name': 'PROXY', 'type': 'select', 'proxies': [n['name'] for n in final_nodes]}],
            'rules': ['MATCH,PROXY']
        }
        with open(OUTPUT_CLASH_FILE, 'w', encoding='utf-8') as f:
            yaml.dump(clash_final, f, allow_unicode=True)
        logger.info(f"成功！已保存 {len(final_nodes)} 个节点到 {OUTPUT_CLASH_FILE}")
    else:
        logger.warning("未发现可用节点")

if __name__ == '__main__':
    main()
