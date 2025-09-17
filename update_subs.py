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
import threading
from datetime import datetime
from urllib.parse import unquote, urlparse, parse_qs
import concurrent.futures
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from ping3 import ping  # pip install ping3

# --- 全局配置 ---
SUBSCRIPTION_URLS_FILE = 'sub_urls.txt'
OUTPUT_CLASH_FILE = 'sub_tested.yaml'
UPDATE_TIME_FILE = 'update_time.txt'

MAX_LATENCY_MS = 500
MAX_NODES_LIMIT = 100
REAL_TEST_URL = 'http://www.gstatic.com/generate_204' # Clash API 默认使用 HTTP
API_TEST_TIMEOUT_SECONDS = 3 # API 调用本身的超时

CLASH_BINARY_PATH = './clash'

def random_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def get_free_port():
    """在系统上找到一个空闲的 TCP 端口"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def get_subscription_content(url):
    headers = {'User-Agent': 'Clash/1.11.0'}
    try:
        print(f"获取订阅: {url}")
        response = requests.get(url, timeout=15, headers=headers)
        response.raise_for_status()
        response.encoding = 'utf-8'
        return response.text
    except requests.RequestException as e:
        print(f"获取订阅失败: {url}, 错误: {e}")
        return None

def decode_base64_content(content):
    try:
        if len(content) % 4 != 0:
            content += '=' * (4 - len(content) % 4)
        return base64.b64decode(content.encode('ascii')).decode('utf-8')
    except Exception:
        return None

def parse_node(link):
    link = link.strip()
    if link.startswith('ss://'): return parse_ss_link(link)
    elif link.startswith('vmess://'): return parse_vmess_link(link)
    elif link.startswith('trojan://'): return parse_trojan_link(link)
    elif link.startswith('vless://'): return parse_vless_link(link)
    elif link.startswith('hysteria://'): return parse_hysteria_link(link)
    elif link.startswith('hysteria2://'): return parse_hysteria2_link(link)
    return None
def parse_ss_link(ss_link):
    try:
        parts = urlparse(ss_link); user_info, host_info = parts.netloc.split('@'); server, port = host_info.split(':'); remarks = unquote(parts.fragment) if parts.fragment else f"ss_{server}";
        try: user_info_str = base64.b64decode(user_info).decode('utf-8')
        except: user_info_str = unquote(user_info)
        method, password = user_info_str.split(':', 1);
        return {'name': remarks, 'type': 'ss', 'server': server, 'port': int(port), 'cipher': method, 'password': password, 'udp': True}
    except: return None
def parse_vmess_link(vmess_link):
    try:
        b64_str = vmess_link[8:]; b64_str += '=' * (-len(b64_str) % 4); vmess_data = json.loads(base64.b64decode(b64_str).decode('utf-8'));
        node = {'name': vmess_data.get('ps', vmess_data.get('add')), 'type': 'vmess', 'server': vmess_data.get('add'), 'port': int(vmess_data.get('port')), 'uuid': vmess_data.get('id'), 'alterId': int(vmess_data.get('aid')), 'cipher': vmess_data.get('scy', 'auto'), 'udp': True, 'tls': vmess_data.get('tls') == 'tls', 'network': vmess_data.get('net')}
        if node.get('tls'): node['servername'] = vmess_data.get('sni', vmess_data.get('host', ''))
        if node.get('network') == 'ws': node['ws-opts'] = {'path': vmess_data.get('path', '/'), 'headers': {'Host': vmess_data.get('host')} if vmess_data.get('host') else {}}
        return node
    except: return None
def parse_trojan_link(trojan_link):
    try:
        parts = urlparse(trojan_link); password, host_info = parts.netloc.split('@'); server, port = host_info.split(':'); remarks = unquote(parts.fragment) if parts.fragment else f"trojan_{server}"; params = {k: v[0] for k, v in parse_qs(parts.query).items()};
        return {'name': remarks, 'type': 'trojan', 'server': server, 'port': int(port), 'password': password, 'udp': True, 'sni': params.get('sni', server), 'skip-cert-verify': params.get('allowInsecure', 'false').lower() in ['true', '1']}
    except: return None
def parse_vless_link(vless_link):
    try:
        parts = urlparse(vless_link); uuid, host_info = parts.netloc.split('@'); server, port = host_info.split(':'); remarks = unquote(parts.fragment) if parts.fragment else f"vless_{server}"; params = {k: v[0] for k, v in parse_qs(parts.query).items()};
        node = {'name': remarks, 'type': 'vless', 'server': server, 'port': int(port), 'uuid': uuid, 'udp': True, 'tls': params.get('security') == 'tls', 'network': params.get('type', 'tcp'), 'servername': params.get('sni', server), 'flow': params.get('flow', '')}
        if node.get('network') == 'ws': node['ws-opts'] = {'path': params.get('path', '/'), 'headers': {'Host': params.get('host', server)}}
        elif node.get('network') == 'grpc': node['grpc-opts'] = {'grpc-service-name': params.get('serviceName', '')}
        return node
    except: return None
def parse_hysteria_link(hy_link):
    try:
        parts = urlparse(hy_link); server, port = parts.netloc.split(':'); remarks = unquote(parts.fragment) if parts.fragment else f"hysteria_{server}"; params = {k: v[0] for k, v in parse_qs(parts.query).items()};
        return {'name': remarks, 'type': 'hysteria', 'server': server, 'port': int(port), 'protocol': params.get('protocol', 'udp'), 'auth_str': params.get('auth'), 'up': int(params.get('upmbps', 50)), 'down': int(params.get('downmbps', 100)), 'sni': params.get('peer', server), 'skip-cert-verify': params.get('insecure', '0') == '1'}
    except: return None
def parse_hysteria2_link(hy2_link):
    try:
        parts = urlparse(hy2_link); password, host_info = parts.netloc.split('@'); server, port = host_info.split(':'); remarks = unquote(parts.fragment) if parts.fragment else f"hysteria2_{server}"; params = {k: v[0] for k, v in parse_qs(parts.query).items()};
        return {'name': remarks, 'type': 'hysteria2', 'server': server, 'port': int(port), 'password': password, 'sni': params.get('sni', server), 'skip-cert-verify': params.get('insecure', '0') == '1'}
    except: return None
# --- 节点解析函数结束 ---

def tcp_latency(host, port, timeout=2):
    """TCP 握手延迟（毫秒）"""
    start = time.time()
    try:
        sock = socket.create_connection((host, port), timeout)
        sock.close()
        return round((time.time() - start) * 1000)
    except:
        return -1

def icmp_latency(host, timeout=2):
    """ICMP ping 延迟（毫秒）"""
    try:
        delay = ping(host, timeout=timeout)
        return round(delay * 1000) if delay else -1
    except:
        return -1

def test_node_latency_with_clash_core(node):
    rand_id = random_string()
    temp_config_path = f'temp_config_{rand_id}.yaml'
    api_port = get_free_port()
    api_address = f'127.0.0.1:{api_port}'
    proxy_name_for_api = node['name'].replace(' ', '_').encode('utf-8', 'ignore').decode('utf-8')
    
    config = {
        'proxies': [node], 'proxy-groups': [{'name': 'test-group', 'type': 'global', 'proxies': [proxy_name_for_api]}],
        'external-controller': api_address, 'log-level': 'silent', 'port': get_free_port(), 'socks-port': get_free_port()
    }
    with open(temp_config_path, 'w', encoding='utf-8') as f: yaml.dump(config, f)

    process = None
    try:
        command = [CLASH_BINARY_PATH, '-f', temp_config_path]
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        if process.poll() is not None: return -1

        api_url = f'http://{api_address}/proxies/{proxy_name_for_api}/delay'
        params = {'url': REAL_TEST_URL, 'timeout': int(API_TEST_TIMEOUT_SECONDS * 1000)}
        response = requests.get(api_url, params=params, timeout=API_TEST_TIMEOUT_SECONDS + 1)
        response.raise_for_status()
        delay_data = response.json()
        return delay_data.get('delay', -1)
    except Exception:
        return -1
    finally:
        if process:
            process.terminate()
            process.wait()
        if os.path.exists(temp_config_path):
            os.remove(temp_config_path)

def ensure_unique_proxy_names(nodes):
    name_counts = {}
    for node in nodes:
        name = node['name']
        if name in name_counts:
            name_counts[name] += 1
            node['name'] = f"{name}_{name_counts[name]}"
        else:
            name_counts[name] = 1
    return nodes

def generate_clash_config(fast_nodes, output_filename):
    if not fast_nodes:
        print(f"没有可用的节点，无法生成 {output_filename}")
        return
    print(f"正在为 {len(fast_nodes)} 个节点生成 {output_filename}...")
    
    clash_config = {
        'port': 7890, 'socks-port': 7891, 'allow-lan': False, 'mode': 'rule',
        'log-level': 'info', 'external-controller': '127.0.0.1:9090',
        'dns': {
            'enabled': True, 'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16',
            'nameserver': ['https://doh.pub/dns-query', 'https://223.5.5.5/dns-query'],
            'fallback': ['8.8.8.8', '1.1.1.1', 'tls://dns.google:853']
        }
    }
    clash_config['proxies'] = fast_nodes
    proxy_names = [node['name'] for node in fast_nodes]
    clash_config['proxy-groups'] = [
        {'name': 'PROXY', 'type': 'select', 'proxies': ['AUTO-URL', 'DIRECT'] + proxy_names},
        {'name': 'AUTO-URL', 'type': 'url-test', 'proxies': proxy_names,
         'url': 'http://www.gstatic.com/generate_204', 'interval': 200}
    ]
    clash_config['rules'] = ['GEOIP,CN,DIRECT', 'MATCH,PROXY'] # 你可以替换成自己的复杂规则列表
    
    with open(output_filename, 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
    print(f"成功生成 Clash 订阅文件: {output_filename}")

def main():
    if not os.path.exists(CLASH_BINARY_PATH):
        print(f"错误: Clash 核心文件未在 '{CLASH_BINARY_PATH}' 找到。")
        sys.exit(1)

    if not os.path.exists(SUBSCRIPTION_URLS_FILE):
        print(f"错误: 订阅文件 {SUBSCRIPTION_URLS_FILE} 不存在。")
        with open(SUBSCRIPTION_URLS_FILE, 'w', encoding='utf-8') as f: f.write("# 在这里粘贴你的订阅链接\n")
        return

    with open(SUBSCRIPTION_URLS_FILE, 'r', encoding='utf-8') as f:
        subscription_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    if not subscription_urls:
        print("订阅文件中没有找到有效的链接。")
        return

    print(f"找到 {len(subscription_urls)} 个订阅链接。")
    all_nodes, unique_nodes_set = [], set()

    for url in subscription_urls:
        content = get_subscription_content(url)
        if not content: continue
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict) and 'proxies' in data and isinstance(data['proxies'], list):
                for proxy in data['proxies']:
                    if all(k in proxy for k in ['name', 'server', 'port', 'type']):
                        node_id = f"{proxy['type']}://{proxy['server']}:{proxy['port']}"
                        if node_id not in unique_nodes_set: all_nodes.append(proxy); unique_nodes_set.add(node_id)
                continue
        except Exception: pass
        decoded_content = decode_base64_content(content)
        links_content = decoded_content if decoded_content else content
        for link in links_content.splitlines():
            node = parse_node(link)
            if node:
                node_id = f"{node['type']}://{node['server']}:{node['port']}"
                if node_id not in unique_nodes_set: all_nodes.append(node); unique_nodes_set.add(node_id)
    
    print(f"去重后共解析出 {len(all_nodes)} 个节点。")
    if not all_nodes: return

    print("\n--- 开始使用 Clash Core 进行真实延迟测试 (并发) ---")
    node_results = []
    max_workers = min(16, len(all_nodes))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_node = {executor.submit(test_node_latency_with_clash_core, node): node for node in all_nodes}
        for future in tqdm(concurrent.futures.as_completed(future_to_node), total=len(all_nodes), desc="测试节点"):
            node = future_to_node[future]
            try:
                latency = future.result()
                if 0 < latency < MAX_LATENCY_MS:
                    node_results.append({'node': node, 'latency': latency})
            except Exception: pass

    node_results.sort(key=lambda x: x['latency'])
    fast_nodes = []
    for item in node_results:
        node = item['node']
        latency = item['latency']
        node['name'] = f"{node['name']} | {latency}ms" # 将延迟附加到节点名称
        fast_nodes.append(node)
        
    fast_nodes = fast_nodes[:MAX_NODES_LIMIT]
    fast_nodes = ensure_unique_proxy_names(fast_nodes)

    print(f"\n--- 测试结束 ---\n筛选出 {len(fast_nodes)} 个可用节点。")
    generate_clash_config(fast_nodes, OUTPUT_CLASH_FILE)

    with open(UPDATE_TIME_FILE, 'w', encoding='utf-8') as f:
        update_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        f.write(f"最后更新时间: {update_time}\n可用节点数量: {len(fast_nodes)}\n")
    print(f"成功记录更新时间: {UPDATE_TIME_FILE}")

if __name__ == '__main__':
    main()
