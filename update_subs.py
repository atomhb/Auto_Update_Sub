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
from datetime import datetime
from urllib.parse import unquote, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import hashlib

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# ==================== 全局配置 ====================
SUBSCRIPTION_URLS_FILE = 'sub_urls.txt'
OUTPUT_CLASH_FILE = 'sub.yaml'
UPDATE_TIME_FILE = 'update_time.txt'

# 两阶段测试配置
STAGE1_V2RAY_TEST = True       # 是否启用V2ray快速测试
STAGE1_TOP_N = 300             # 第一阶段保留前N个低延迟节点
STAGE2_SCHOLAR_TEST = True     # 第二阶段是否验证Google Scholar

# V2ray测试配置
V2RAY_BINARY_PATH = './v2ray'  # V2ray核心路径
V2RAY_TEST_TIMEOUT = 10        # V2ray测试超时(秒)
V2RAY_TEST_URL = 'https://www.google.com/generate_204'

# Clash测试配置
CLASH_BINARY_PATH = './clash'
MAX_LATENCY_MS = 500
MAX_NODES_LIMIT = 100

# 并发控制
MAX_WORKERS_FETCH = 10
MAX_WORKERS_V2RAY = 16         # V2ray测试并发数（可以更高）
MAX_WORKERS_CLASH = 6          # Clash测试并发数

# 学术验证配置
SCHOLAR_VERIFY_URL = 'https://scholar.google.com/scholar?q=test'
SCHOLAR_KEYWORDS = ['scholar', 'articles', 'cited by']

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('test.log', encoding='utf-8')
    ]
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
    defaults = {'udp': True, 'skip-cert-verify': False}
    for key, value in defaults.items():
        node.setdefault(key, value)
    return node

# ==================== 订阅获取和解析 ====================
def get_subscription_content(url):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'}
    try:
        logger.info(f"获取订阅: {url[:60]}...")
        response = requests.get(url, timeout=20, headers=headers)
        response.raise_for_status()
        response.encoding = 'utf-8'
        return response.text
    except Exception as e:
        logger.error(f"获取订阅失败: {e}")
        return None

def decode_base64_content(content):
    try:
        padding = (4 - len(content) % 4) % 4
        content += '=' * padding
        return base64.b64decode(content.encode('ascii')).decode('utf-8')
    except:
        return None

def parse_node(link):
    """解析节点链接（简化版，保留主要类型）"""
    link = link.strip()
    if link.startswith('vmess://'): return parse_vmess_link(link)
    elif link.startswith('vless://'): return parse_vless_link(link)
    elif link.startswith('trojan://'): return parse_trojan_link(link)
    elif link.startswith('ss://'): return parse_ss_link(link)
    return None

def parse_vmess_link(link):
    try:
        b64_str = link[8:]
        padding = (4 - len(b64_str) % 4) % 4
        data = json.loads(base64.b64decode(b64_str + '=' * padding).decode('utf-8'))
        if not all(k in data for k in ['add', 'port', 'id']):
            return None
        node = {
            'name': data.get('ps', data['add']),
            'type': 'vmess',
            'server': data['add'],
            'port': int(data['port']),
            'uuid': data['id'],
            'alterId': int(data.get('aid', 0)),
            'cipher': data.get('scy', 'auto'),
            'tls': data.get('tls') == 'tls',
            'network': data.get('net', 'tcp')
        }
        if node['network'] == 'ws':
            node['ws-opts'] = {'path': data.get('path', '/'), 'headers': {'Host': data.get('host', '')}}
        return standardize_node(node)
    except:
        return None

def parse_vless_link(link):
    try:
        parts = urlparse(link)
        if '@' not in parts.netloc:
            return None
        uuid, host_info = parts.netloc.split('@', 1)
        server, port = host_info.rsplit(':', 1)
        params = {k: v[0] for k, v in parse_qs(parts.query).items()}
        node = {
            'name': unquote(parts.fragment) if parts.fragment else f"vless_{server}",
            'type': 'vless',
            'server': server,
            'port': int(port),
            'uuid': uuid,
            'network': params.get('type', 'tcp'),
            'tls': params.get('security') == 'tls'
        }
        return standardize_node(node)
    except:
        return None

def parse_trojan_link(link):
    try:
        parts = urlparse(link)
        if '@' not in parts.netloc:
            return None
        password, host_info = parts.netloc.split('@', 1)
        server, port = host_info.rsplit(':', 1)
        params = {k: v[0] for k, v in parse_qs(parts.query).items()}
        node = {
            'name': unquote(parts.fragment) if parts.fragment else f"trojan_{server}",
            'type': 'trojan',
            'server': server,
            'port': int(port),
            'password': password,
            'sni': params.get('sni', server),
            'skip-cert-verify': params.get('allowInsecure', '0') in ['1', 'true']
        }
        return standardize_node(node)
    except:
        return None

def parse_ss_link(link):
    try:
        parts = urlparse(link)
        if '@' not in parts.netloc:
            return None
        user_info, host_info = parts.netloc.split('@', 1)
        server, port = host_info.rsplit(':', 1)
        try:
            user_info_str = base64.urlsafe_b64decode(user_info + '===').decode('utf-8')
        except:
            user_info_str = unquote(user_info)
        method, password = user_info_str.split(':', 1)
        node = {
            'name': unquote(parts.fragment) if parts.fragment else f"ss_{server}",
            'type': 'ss',
            'server': server,
            'port': int(port),
            'cipher': method,
            'password': password
        }
        return standardize_node(node)
    except:
        return None

def parse_all_nodes(all_contents):
    """解析所有订阅节点"""
    all_nodes = []
    unique_set = set()

    for url, content in all_contents.items():
        nodes = []
        # YAML解析
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict) and 'proxies' in data:
                for proxy in data['proxies']:
                    if all(k in proxy for k in ['name', 'server', 'port', 'type']):
                        node = standardize_node(proxy)
                        h = node_hash(node)
                        if h not in unique_set:
                            nodes.append(node)
                            unique_set.add(h)
        except:
            pass

        # 链接解析
        if not nodes:
            decoded = decode_base64_content(content) or content
            for link in decoded.splitlines():
                node = parse_node(link)
                if node:
                    h = node_hash(node)
                    if h not in unique_set:
                        nodes.append(node)
                        unique_set.add(h)

        all_nodes.extend(nodes)
        logger.info(f"订阅解析: {len(nodes)} 个节点")

    logger.info(f"总解析: {len(all_nodes)} 个唯一节点")
    return all_nodes

# ==================== 阶段1: V2ray快速延迟测试 ====================
def generate_v2ray_config(node, socks_port, http_port):
    """生成V2ray配置"""
    config = {
        "log": {"loglevel": "none"},
        "inbounds": [
            {"port": socks_port, "protocol": "socks", "settings": {"udp": True}},
            {"port": http_port, "protocol": "http"}
        ],
        "outbounds": [{"protocol": "freedom"}]
    }

    # 根据节点类型构建outbound
    if node['type'] == 'vmess':
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": node['server'],
                    "port": node['port'],
                    "users": [{
                        "id": node['uuid'],
                        "alterId": node.get('alterId', 0),
                        "security": node.get('cipher', 'auto')
                    }]
                }]
            },
            "streamSettings": {
                "network": node.get('network', 'tcp')
            }
        }
        if node.get('tls'):
            outbound['streamSettings']['security'] = 'tls'
        config['outbounds'] = [outbound]

    elif node['type'] == 'vless':
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": node['server'],
                    "port": node['port'],
                    "users": [{"id": node['uuid'], "encryption": "none"}]
                }]
            },
            "streamSettings": {"network": node.get('network', 'tcp')}
        }
        if node.get('tls'):
            outbound['streamSettings']['security'] = 'tls'
        config['outbounds'] = [outbound]

    elif node['type'] == 'trojan':
        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": node['server'],
                    "port": node['port'],
                    "password": node['password']
                }]
            },
            "streamSettings": {"security": "tls", "tlsSettings": {"serverName": node.get('sni', node['server'])}}
        }
        config['outbounds'] = [outbound]

    elif node['type'] == 'ss':
        outbound = {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": node['server'],
                    "port": node['port'],
                    "method": node['cipher'],
                    "password": node['password']
                }]
            }
        }
        config['outbounds'] = [outbound]

    return config

def test_node_with_v2ray(node):
    """使用V2ray测试节点延迟"""
    rand_id = random_string()
    config_path = f'v2ray_{rand_id}.json'
    socks_port = get_free_port()
    http_port = get_free_port()

    try:
        config = generate_v2ray_config(node, socks_port, http_port)
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f)

        # 启动V2ray
        process = subprocess.Popen(
            [V2RAY_BINARY_PATH, 'run', '-c', config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        time.sleep(1)  # 等待启动

        # 通过代理测试延迟
        proxies = {'http': f'http://127.0.0.1:{http_port}', 'https': f'http://127.0.0.1:{http_port}'}

        start = time.time()
        try:
            response = requests.get(
                V2RAY_TEST_URL,
                proxies=proxies,
                timeout=V2RAY_TEST_TIMEOUT,
                verify=False
            )
            if response.status_code in [200, 204]:
                delay = round((time.time() - start) * 1000)
                logger.info(f"✓ V2ray测试 {node['name']}: {delay}ms")
                return delay
        except:
            pass

        return -1

    except Exception as e:
        logger.debug(f"V2ray测试失败 {node['name']}: {e}")
        return -1
    finally:
        try:
            process.terminate()
            process.wait(timeout=2)
        except:
            try:
                process.kill()
            except:
                pass
        try:
            os.remove(config_path)
        except:
            pass

def stage1_v2ray_test(nodes):
    """阶段1: V2ray批量测试"""
    logger.info(f"\n{'='*60}")
    logger.info(f"[阶段1/2] V2ray快速延迟测试 ({len(nodes)} 个节点)")
    logger.info(f"{'='*60}")

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_V2RAY) as executor:
        futures = {executor.submit(test_node_with_v2ray, node): node for node in nodes}

        for future in tqdm(as_completed(futures), total=len(nodes), desc="V2ray测试"):
            node = futures[future]
            try:
                delay = future.result(timeout=V2RAY_TEST_TIMEOUT + 5)
                if 0 < delay < MAX_LATENCY_MS * 2:
                    results.append({'node': node, 'delay': delay})
            except:
                pass

    # 按延迟排序，取前N个
    results.sort(key=lambda x: x['delay'])
    top_nodes = results[:STAGE1_TOP_N]

    logger.info(f"✓ 阶段1完成: {len(top_nodes)}/{len(nodes)} 个节点通过")
    return [item['node'] for item in top_nodes]

# ==================== 阶段2: Clash学术验证 ====================
def wait_for_clash_api(api_address, timeout=10):
    api_base = f'http://{api_address}'
    start = time.time()
    while time.time() - start < timeout:
        try:
            response = requests.get(f'{api_base}/version', timeout=1)
            if response.status_code == 200:
                return True
        except:
            pass
        time.sleep(0.3)
    return False

def verify_scholar_access(socks_address, node_name):
    """验证Google Scholar访问"""
    if not STAGE2_SCHOLAR_TEST:
        return True

    try:
        proxies = {'http': f'socks5h://{socks_address}', 'https': f'socks5h://{socks_address}'}
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'}

        response = requests.get(SCHOLAR_VERIFY_URL, proxies=proxies, timeout=12, headers=headers, verify=False)

        if response.status_code == 200:
            content_lower = response.text.lower()
            has_scholar = any(kw in content_lower for kw in SCHOLAR_KEYWORDS)
            is_blocked = 'captcha' in content_lower or 'automated queries' in content_lower

            if has_scholar and not is_blocked:
                logger.info(f"✓ Scholar可访问: {node_name}")
                return True
    except:
        pass

    return False

def test_node_with_clash_scholar(node):
    """Clash测试 + Scholar验证"""
    rand_id = random_string()
    config_path = f'clash_{rand_id}.yaml'
    api_port = get_free_port()
    socks_port = get_free_port()

    config = {
        'proxies': [node],
        'external-controller': f'127.0.0.1:{api_port}',
        'socks-port': socks_port,
        'log-level': 'silent'
    }

    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config, f)

        process = subprocess.Popen(
            [CLASH_BINARY_PATH, '-f', config_path, '-d', '.'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        if not wait_for_clash_api(f'127.0.0.1:{api_port}'):
            return None

        # 学术验证
        if verify_scholar_access(f'127.0.0.1:{socks_port}', node['name']):
            return node

        return None

    except:
        return None
    finally:
        try:
            process.terminate()
            process.wait(timeout=2)
        except:
            try:
                process.kill()
            except:
                pass
        try:
            os.remove(config_path)
        except:
            pass
        time.sleep(0.3)

def stage2_clash_scholar_test(nodes):
    """阶段2: Clash学术验证"""
    logger.info(f"\n{'='*60}")
    logger.info(f"[阶段2/2] Clash + Google Scholar验证 ({len(nodes)} 个节点)")
    logger.info(f"{'='*60}")

    valid_nodes = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_CLASH) as executor:
        futures = {executor.submit(test_node_with_clash_scholar, node): node for node in nodes}

        for future in tqdm(as_completed(futures), total=len(nodes), desc="Scholar验证"):
            try:
                result = future.result(timeout=30)
                if result:
                    valid_nodes.append(result)
                    if len(valid_nodes) >= MAX_NODES_LIMIT:
                        # 达到目标数量，取消剩余任务
                        for f in futures:
                            f.cancel()
                        break
            except:
                pass
            time.sleep(random.uniform(0.4, 0.8))

    logger.info(f"✓ 阶段2完成: {len(valid_nodes)} 个节点通过Scholar验证")
    return valid_nodes

# ==================== 配置文件生成 ====================
def ensure_unique_names(nodes):
    name_counts = {}
    for node in nodes:
        name = node['name']
        if name in name_counts:
            name_counts[name] += 1
            node['name'] = f"{name}_{name_counts[name]}"
        else:
            name_counts[name] = 1
    return nodes

def generate_clash_config(nodes, output_file):
    logger.info(f"生成配置: {len(nodes)} 个节点 -> {output_file}")

    config = {
        'port': 7890,
        'socks-port': 7891,
        'allow-lan': False,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'dns': {
            'enabled': True,
            'enhanced-mode': 'fake-ip',
            'nameserver': ['https://doh.pub/dns-query', 'https://223.5.5.5/dns-query'],
            'fallback': ['8.8.8.8', '1.1.1.1']
        },
        'proxies': nodes
    }

    if nodes:
        proxy_names = [n['name'] for n in nodes]
        config['proxy-groups'] = [
            {'name': 'PROXY', 'type': 'select', 'proxies': ['AUTO'] + proxy_names},
            {'name': 'AUTO', 'type': 'url-test', 'proxies': proxy_names,
             'url': 'http://www.gstatic.com/generate_204', 'interval': 300}
        ]
    else:
        config['proxy-groups'] = [{'name': 'PROXY', 'type': 'select', 'proxies': ['DIRECT']}]

    config['rules'] = [
        'DOMAIN-SUFFIX,scholar.google.com,PROXY',
        'DOMAIN-SUFFIX,google.com,PROXY',
        'GEOIP,CN,DIRECT',
        'MATCH,PROXY'
    ]

    with open(output_file, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

    logger.info(f"✓ 配置文件已生成")

# ==================== 主流程 ====================
def main():
    logger.info("="*60)
    logger.info("Clash Google Scholar测试 - 两阶段优化方案")
    logger.info("="*60)

    # 检查核心文件
    if STAGE1_V2RAY_TEST and not os.path.exists(V2RAY_BINARY_PATH):
        logger.error(f"V2ray核心未找到: {V2RAY_BINARY_PATH}")
        logger.info("请下载: https://github.com/v2fly/v2ray-core/releases")
        sys.exit(1)

    if not os.path.exists(CLASH_BINARY_PATH):
        logger.error(f"Clash核心未找到: {CLASH_BINARY_PATH}")
        sys.exit(1)

    # 读取订阅
    if not os.path.exists(SUBSCRIPTION_URLS_FILE):
        with open(SUBSCRIPTION_URLS_FILE, 'w') as f:
            f.write("# 订阅链接\n")
        logger.error(f"请在 {SUBSCRIPTION_URLS_FILE} 中添加订阅链接")
        return

    with open(SUBSCRIPTION_URLS_FILE, 'r') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    if not urls:
        logger.warning("无有效订阅链接")
        return

    logger.info(f"订阅数量: {len(urls)}")

    # 获取订阅
    logger.info("\n获取订阅内容...")
    contents = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_FETCH) as executor:
        futures = {executor.submit(get_subscription_content, url): url for url in urls}
        for future in as_completed(futures):
            url = futures[future]
            content = future.result()
            if content:
                contents[url] = content

    if not contents:
        logger.warning("所有订阅获取失败")
        return

    logger.info(f"成功获取: {len(contents)}/{len(urls)} 个订阅")

    # 解析节点
    all_nodes = parse_all_nodes(contents)
    if not all_nodes:
        logger.warning("未解析到节点")
        return

    # 阶段1: V2ray测试
    if STAGE1_V2RAY_TEST:
        stage1_nodes = stage1_v2ray_test(all_nodes)
    else:
        stage1_nodes = all_nodes[:STAGE1_TOP_N]

    if not stage1_nodes:
        logger.warning("阶段1无可用节点")
        generate_clash_config([], OUTPUT_CLASH_FILE)
        return

    # 阶段2: Clash Scholar验证
    final_nodes = stage2_clash_scholar_test(stage1_nodes)

    if final_nodes:
        final_nodes = ensure_unique_names(final_nodes)
        generate_clash_config(final_nodes, OUTPUT_CLASH_FILE)

        with open(UPDATE_TIME_FILE, 'w') as f:
            f.write(f"更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"可用节点: {len(final_nodes)}\n")
            f.write(f"订阅来源: {len(contents)}\n")

        logger.info(f"\n{'='*60}")
        logger.info(f"✓ 完成！共 {len(final_nodes)} 个Google Scholar可用节点")
        logger.info(f"{'='*60}")
    else:
        logger.warning("无可用节点")
        generate_clash_config([], OUTPUT_CLASH_FILE)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\n用户中断")
        sys.exit(0)
    except Exception as e:
        logger.error(f"错误: {e}", exc_info=True)
        sys.exit(1)
