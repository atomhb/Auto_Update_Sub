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
import logging
from datetime import datetime
from urllib.parse import unquote, urlparse, parse_qs
import concurrent.futures
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from ping3 import ping  # pip install ping3
import hashlib  # 内置，用于去重哈希
from itertools import islice  # 内置，用于分批

try:
    import psutil  # pip install psutil，可选，用于杀进程
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# --- 全局配置 ---
SUBSCRIPTION_URLS_FILE = 'sub_urls.txt'
OUTPUT_CLASH_FILE = 'sub.yaml'
UPDATE_TIME_FILE = 'update_time.txt'

MAX_LATENCY_MS = 500
MAX_NODES_LIMIT = 100
REAL_TEST_URLS = [
    'http://cp.cloudflare.com/generate_204',
    'http://www.google.com/generate_204',
    'https://scholar.google.com/scholar_labs/search'
]  # 多URL轮换，避免劫持
API_TEST_TIMEOUT_SECONDS = 10  # 延长超时
PING_THRESHOLD_MS = 200  # 预筛选阈值
MAX_RETRIES = 3  # API重试次数
BATCH_SIZE = 1000  # 分批大小，适用于4w+节点
PRESCREEN_ENABLED = True  # 可设为 False 禁用预筛选
DEBUG_MODE = True  # 启用详细日志

CLASH_BINARY_PATH = './clash'

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def random_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def get_free_port():
    """在系统上找到一个空闲的 TCP 端口"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def wait_for_clash_api(api_address, timeout=10):
    """循环检查 Clash API 是否已启动"""
    api_base = f'http://{api_address}'
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            # 优先/version，备选/traffic
            for endpoint in ['/version', '/traffic']:
                response = requests.get(f'{api_base}{endpoint}', timeout=1)
                if response.status_code == 200:
                    return True
        except requests.exceptions.ConnectionError:
            pass
        except Exception:
            pass
        time.sleep(0.2)
    return False

def get_subscription_content(url):
    headers = {'User-Agent': 'Clash/1.11.0'}
    try:
        logger.info(f"获取订阅: {url}")
        response = requests.get(url, timeout=15, headers=headers)
        response.raise_for_status()
        response.encoding = 'utf-8'
        return response.text
    except requests.RequestException as e:
        logger.error(f"获取订阅失败: {url}, 错误: {e}")
        return None

def decode_base64_content(content):
    try:
        if len(content) % 4 != 0:
            padding = (4 - len(content) % 4) % 4
            content += '=' * padding
        return base64.b64decode(content.encode('ascii')).decode('utf-8')
    except Exception as e:
        logger.warning(f"Base64解码失败: {e}")
        return None

def node_hash(node):
    """生成节点哈希用于去重"""
    return hashlib.md5(json.dumps(node, sort_keys=True).encode()).hexdigest()

def standardize_node(node):
    """标准化节点，添加默认字段"""
    defaults = {'udp': True, 'tls': False, 'skip-cert-verify': False, 'network': 'tcp'}
    for key, value in defaults.items():
        node.setdefault(key, value)
    return node

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
        parts = urlparse(ss_link)
        if '@' not in parts.netloc:
            logger.warning(f"SS链接格式异常，无@: {ss_link[:50]}...")
            return None
        user_info, host_info = parts.netloc.split('@', 1)
        server, port = host_info.split(':', 1)
        remarks = unquote(parts.fragment) if parts.fragment else f"ss_{server}"
        try:
            user_info_str = base64.urlsafe_b64decode(user_info + '===').decode('utf-8')  # URL-safe b64
        except:
            user_info_str = unquote(user_info)
        method, password = user_info_str.split(':', 1)
        node = {'name': remarks, 'type': 'ss', 'server': server, 'port': int(port), 'cipher': method, 'password': password}
        return standardize_node(node)
    except Exception as e:
        logger.warning(f"解析SS失败: {e}")
        return None

def parse_vmess_link(vmess_link):
    try:
        b64_str = vmess_link[8:]
        padding = (4 - len(b64_str) % 4) % 4
        b64_str += '=' * padding
        vmess_data = json.loads(base64.b64decode(b64_str).decode('utf-8'))
        if not all(key in vmess_data for key in ['add', 'port', 'id']):
            return None
        node = {
            'name': vmess_data.get('ps', vmess_data.get('add', '')),
            'type': 'vmess',
            'server': vmess_data['add'],
            'port': int(vmess_data['port']),
            'uuid': vmess_data['id'],
            'alterId': int(vmess_data.get('aid', 0)),
            'cipher': vmess_data.get('scy', 'auto')
        }
        node['tls'] = vmess_data.get('tls') == 'tls'
        if node['tls']:
            node['servername'] = vmess_data.get('sni', vmess_data.get('host', ''))
        node['network'] = vmess_data.get('net', 'tcp')
        if node['network'] == 'ws':
            node['ws-opts'] = {'path': vmess_data.get('path', '/'), 'headers': {'Host': vmess_data.get('host', '')}}
        return standardize_node(node)
    except Exception as e:
        logger.warning(f"解析VMess失败: {e}")
        return None

def parse_trojan_link(trojan_link):
    try:
        parts = urlparse(trojan_link)
        if '@' not in parts.netloc:
            return None
        password, host_info = parts.netloc.split('@', 1)
        server, port = host_info.split(':', 1)
        remarks = unquote(parts.fragment) if parts.fragment else f"trojan_{server}"
        params = {k: v[0] for k, v in parse_qs(parts.query).items()}
        node = {
            'name': remarks,
            'type': 'trojan',
            'server': server,
            'port': int(port),
            'password': password,
            'sni': params.get('sni', server),
            'skip-cert-verify': params.get('allowInsecure', '0') in ['1', 'true']
        }
        return standardize_node(node)
    except Exception as e:
        logger.warning(f"解析Trojan失败: {e}")
        return None

def parse_vless_link(vless_link):
    try:
        parts = urlparse(vless_link)
        if '@' not in parts.netloc:
            return None
        uuid, host_info = parts.netloc.split('@', 1)
        server, port = host_info.split(':', 1)
        remarks = unquote(parts.fragment) if parts.fragment else f"vless_{server}"
        params = {k: v[0] for k, v in parse_qs(parts.query).items()}
        node = {
            'name': remarks,
            'type': 'vless',
            'server': server,
            'port': int(port),
            'uuid': uuid,
            'network': params.get('type', 'tcp'),
            'servername': params.get('sni', server),
            'flow': params.get('flow', '')
        }
        node['tls'] = params.get('security') == 'tls'
        if node['network'] == 'ws':
            node['ws-opts'] = {'path': params.get('path', '/'), 'headers': {'Host': params.get('host', server)}}
        elif node['network'] == 'grpc':
            node['grpc-opts'] = {'grpc-service-name': params.get('serviceName', '')}
        return standardize_node(node)
    except Exception as e:
        logger.warning(f"解析VLESS失败: {e}")
        return None

def parse_hysteria_link(hy_link):
    try:
        parts = urlparse(hy_link)
        netloc = parts.netloc
        if ':' not in netloc:
            return None
        server, port = netloc.split(':', 1)
        remarks = unquote(parts.fragment) if parts.fragment else f"hysteria_{server}"
        params = {k: v[0] for k, v in parse_qs(parts.query).items()}
        node = {
            'name': remarks,
            'type': 'hysteria',
            'server': server,
            'port': int(port),
            'protocol': params.get('protocol', 'udp'),
            'auth_str': params.get('auth', ''),
            'up': int(params.get('upmbps', 50)),
            'down': int(params.get('downmbps', 100)),
            'sni': params.get('peer', server),
            'skip-cert-verify': params.get('insecure', '0') == '1'
        }
        return standardize_node(node)
    except Exception as e:
        logger.warning(f"解析Hysteria失败: {e}")
        return None

def parse_hysteria2_link(hy2_link):
    try:
        parts = urlparse(hy2_link)
        if '@' not in parts.netloc:
            return None
        password, host_info = parts.netloc.split('@', 1)
        server, port = host_info.split(':', 1)
        remarks = unquote(parts.fragment) if parts.fragment else f"hysteria2_{server}"
        params = {k: v[0] for k, v in parse_qs(parts.query).items()}
        node = {
            'name': remarks,
            'type': 'hysteria2',
            'server': server,
            'port': int(port),
            'password': password,
            'sni': params.get('sni', server),
            'skip-cert-verify': params.get('insecure', '0') == '1'
        }
        return standardize_node(node)
    except Exception as e:
        logger.warning(f"解析Hysteria2失败: {e}")
        return None

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

def kill_clash_process(process):
    """杀Clash进程"""
    if process.poll() is None:
        try:
            process.terminate()
            process.wait(timeout=3)
        except:
            if HAS_PSUTIL:
                for child in process.children(recursive=True):
                    child.kill()
                process.kill()
            else:
                process.kill()

def test_node_latency_with_clash_core(node):
    rand_id = random_string()
    temp_config_path = f'temp_config_{rand_id}.yaml'
    api_port = get_free_port()
    api_address = f'127.0.0.1:{api_port}'
    proxy_name_for_api = requests.utils.quote(node['name'])
    
    config = {
        'proxies': [node],
        'proxy-groups': [{'name': 'test-group', 'type': 'select', 'proxies': [node['name']]}],
        'unified-delay': True,  # 强制完整延迟测试
        'external-controller': api_address,
        'log-level': 'silent',
        'port': get_free_port(),
        'socks-port': get_free_port(),
        'mixed-port': get_free_port()  # 避免端口冲突
    }
    with open(temp_config_path, 'w', encoding='utf-8') as f:
        yaml.dump(config, f)

    process = None
    try:
        command = [CLASH_BINARY_PATH, '-f', temp_config_path, '-d', '.']
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not wait_for_clash_api(api_address, timeout=10):
            logger.warning(f"Clash API 启动失败: {node['name']}")
            return -1
        if process.poll() is not None:
            return -1

        delays = []
        for _ in range(MAX_RETRIES):
            for test_url in REAL_TEST_URLS:
                api_url = f'http://{api_address}/proxies/{proxy_name_for_api}/delay'
                params = {'url': test_url, 'timeout': int(API_TEST_TIMEOUT_SECONDS * 1000)}
                try:
                    response = requests.get(api_url, params=params, timeout=API_TEST_TIMEOUT_SECONDS + 2)
                    response.raise_for_status()
                    delay_data = response.json()
                    delay = delay_data.get('delay', -1)
                    if delay > 0:
                        delays.append(delay)
                except Exception as e:
                    logger.debug(f"API测试失败 {test_url}: {e}")
            if delays:
                break
            time.sleep(1)  # 重试间隔
        avg_delay = sum(delays) / len(delays) if delays else -1
        return round(avg_delay) if avg_delay > 0 else -1
    except Exception as e:
        logger.error(f"节点测试错误 {node['name']}: {e}")
        return -1
    finally:
        if process:
            kill_clash_process(process)
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

def chunks(iterable, size):
    """分批生成器"""
    iterator = iter(iterable)
    for first in iterator:
        yield list(islice(iterator, size - 1, None)) + [first] if size > 1 else [first]

def generate_clash_config(fast_nodes, output_filename):
    logger.info(f"调用 generate_clash_config: 输入 {len(fast_nodes)} 个节点，输出 {output_filename}...")
    
    # 验证节点完整性
    invalid_nodes = []
    for node in fast_nodes[:]:  # 复制以避免修改时删除
        if not all(key in node for key in ['name', 'type', 'server', 'port']):
            invalid_nodes.append(node['name'])
            fast_nodes.remove(node)
    if invalid_nodes:
        logger.warning(f"移除 {len(invalid_nodes)} 个无效节点: {invalid_nodes[:3]}...")  # 只显示前3个
    
    if not fast_nodes:
        logger.warning(f"无可用节点，生成空配置 {output_filename}")
    
    clash_config = {
        'port': 7890,
        'socks-port': 7891,
        'allow-lan': False,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'unified-delay': True,  # 全局启用真实延迟
        'dns': {
            'enabled': True,
            'enhanced-mode': 'fake-ip',
            'fake-ip-range': '198.18.0.1/16',
            'nameserver': ['https://doh.pub/dns-query', 'https://223.5.5.5/dns-query'],
            'fallback': ['8.8.8.8', '1.1.1.1', 'tls://dns.google:853']
        },
        'proxies': fast_nodes  # 即使空，也写入 []
    }
    proxy_names = [node['name'] for node in fast_nodes]
    clash_config['proxy-groups'] = [
        {'name': 'PROXY', 'type': 'select', 'proxies': ['AUTO-URL', 'DIRECT'] + proxy_names},
        {'name': 'AUTO-URL', 'type': 'url-test', 'proxies': proxy_names,
         'url': 'http://cp.cloudflare.com/generate_204', 'interval': 300}  # 延长间隔
    ]
    clash_config['rules'] = [
        'GEOIP,CN,DIRECT',
        'MATCH,PROXY'
    ]  # 可扩展更多规则
    
    try:
        with open(output_filename, 'w', encoding='utf-8') as f:
            yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
        logger.info(f"成功生成/更新 Clash 订阅文件: {output_filename} (节点数: {len(fast_nodes)})")
    except Exception as e:
        logger.error(f"写入 YAML 失败: {e}")

# 新增：统一解析所有订阅节点
def parse_all_nodes(all_contents):
    all_nodes = []
    unique_nodes_set = set()
    for url, content in all_contents.items():
        this_nodes = []
        # 先试YAML解析
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict) and 'proxies' in data and isinstance(data['proxies'], list):
                for proxy in data['proxies']:
                    if all(k in proxy for k in ['name', 'server', 'port', 'type']):
                        node = standardize_node(proxy)
                        node_hash_val = node_hash(node)
                        if node_hash_val not in unique_nodes_set:
                            node['source'] = url  # 添加来源标签，便于调试
                            this_nodes.append(node)
                            unique_nodes_set.add(node_hash_val)
                if DEBUG_MODE:
                    logger.info(f"YAML订阅 {url} 解析出 {len(this_nodes)} 个节点。")
        except Exception as e:
            logger.debug(f"YAML解析失败 for {url}: {e}")

        if not this_nodes:  # Fallback: base64/链接解析
            decoded_content = decode_base64_content(content)
            links_content = decoded_content if decoded_content else content
            for link in links_content.splitlines():
                node = parse_node(link)
                if node:
                    node_hash_val = node_hash(node)
                    if node_hash_val not in unique_nodes_set:
                        node['source'] = url  # 添加来源标签
                        this_nodes.append(node)
                        unique_nodes_set.add(node_hash_val)
            if DEBUG_MODE:
                logger.info(f"链接订阅 {url} 解析出 {len(this_nodes)} 个节点。")

        all_nodes.extend(this_nodes)
        logger.info(f"订阅 {url} 解析出 {len(this_nodes)} 个节点，全局累积 {len(all_nodes)} 个。")
    
    logger.info(f"总解析 {len(all_nodes)} 个唯一节点（全局去重）。")
    return all_nodes

# 新增：统一预筛选所有节点
def prefilter_all_nodes(all_nodes):
    if not PRESCREEN_ENABLED:
        return all_nodes[:]
    
    logger.info(f"全局预筛选 {len(all_nodes)} 个节点...")
    prefiltered_nodes = []
    failed_count = 0
    for node in all_nodes:
        icmp = icmp_latency(node['server'])
        if icmp > PING_THRESHOLD_MS or icmp == -1:
            logger.debug(f"节点 {node['name']} ping 失败: {icmp}ms")
            failed_count += 1
            continue
        tcp = tcp_latency(node['server'], node['port'])
        if tcp > 0 and tcp < MAX_LATENCY_MS * 2:
            prefiltered_nodes.append(node)
            logger.debug(f"预筛选通过 {node['name']}: ping={icmp}ms, tcp={tcp}ms")
        else:
            logger.debug(f"节点 {node['name']} TCP 失败: {tcp}ms")
            failed_count += 1
    logger.info(f"全局预筛选后剩余 {len(prefiltered_nodes)} 个节点 ({failed_count} 个失败）。")
    return prefiltered_nodes

# 新增：批量测试所有预筛选节点延迟
def test_all_nodes_latency(prefiltered_nodes):
    all_results = []
    use_batching = len(prefiltered_nodes) > BATCH_SIZE * 10
    max_workers = min(8, len(prefiltered_nodes))
    
    if use_batching:
        logger.info(f"节点过多，启用分批测试 (批大小: {BATCH_SIZE})...")
        for i, batch in enumerate(chunks(prefiltered_nodes, BATCH_SIZE)):
            logger.info(f"批 {i+1} ({len(batch)} 个节点)...")
            batch_max_workers = min(8, len(batch))
            batch_results = []
            with ThreadPoolExecutor(max_workers=batch_max_workers) as executor:
                future_to_node = {executor.submit(test_node_latency_with_clash_core, node): node for node in batch}
                for future in tqdm(as_completed(future_to_node), total=len(batch), desc=f"批 {i+1} 测试"):
                    node = future_to_node[future]
                    try:
                        latency = future.result()
                        if 0 < latency < MAX_LATENCY_MS:
                            batch_results.append({'node': node, 'latency': latency})
                            logger.info(f"批 {i+1} 成功 {node['name']}: {latency}ms")
                        else:
                            logger.warning(f"批 {i+1} 失败: {node['name']} ({latency}ms)")
                    except Exception as e:
                        logger.error(f"批 {i+1} 异常 {node['name']}: {e}")
            all_results.extend(batch_results)
    else:
        logger.info(f"Clash 测试 {len(prefiltered_nodes)} 个节点 (workers: {max_workers})...")
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_node = {executor.submit(test_node_latency_with_clash_core, node): node for node in prefiltered_nodes}
            for future in tqdm(as_completed(future_to_node), total=len(prefiltered_nodes), desc="全局测试"):
                node = future_to_node[future]
                try:
                    latency = future.result()
                    if 0 < latency < MAX_LATENCY_MS:
                        all_results.append({'node': node, 'latency': latency})
                        logger.info(f"成功 {node['name']}: {latency}ms")
                    else:
                        logger.warning(f"失败: {node['name']} ({latency}ms)")
                except Exception as e:
                    logger.error(f"异常 {node['name']}: {e}")
    
    logger.info(f"测试完成，共 {len(all_results)} 个有效节点。")
    return all_results

def main():
    if not os.path.exists(CLASH_BINARY_PATH):
        logger.error(f"Clash 核心文件未在 '{CLASH_BINARY_PATH}' 找到。")
        sys.exit(1)

    if not os.path.exists(SUBSCRIPTION_URLS_FILE):
        logger.error(f"订阅文件 {SUBSCRIPTION_URLS_FILE} 不存在。")
        with open(SUBSCRIPTION_URLS_FILE, 'w', encoding='utf-8') as f:
            f.write("# 在这里粘贴你的订阅链接\n")
        return

    with open(SUBSCRIPTION_URLS_FILE, 'r', encoding='utf-8') as f:
        subscription_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    if not subscription_urls:
        logger.warning("订阅文件中没有找到有效的链接。")
        generate_clash_config([], OUTPUT_CLASH_FILE)
        return

    logger.info(f"找到 {len(subscription_urls)} 个订阅链接，开始批量处理。")

    # 阶段1: 并发批量获取所有订阅内容
    all_contents = {}
    with ThreadPoolExecutor(max_workers=5) as executor:  # 并发获取，max_workers=5避免限速
        future_to_url = {executor.submit(get_subscription_content, url): url for url in subscription_urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            content = future.result()
            if content:
                all_contents[url] = content
            else:
                logger.warning(f"订阅 {url} 获取失败，跳过。")
    
    if not all_contents:
        logger.warning("所有订阅获取失败，生成空配置。")
        generate_clash_config([], OUTPUT_CLASH_FILE)
        return
    logger.info(f"成功获取 {len(all_contents)} 个订阅内容。")

    # 阶段2: 统一解析所有节点（全局去重）
    all_nodes = parse_all_nodes(all_contents)
    if not all_nodes:
        logger.warning("所有订阅无有效节点，生成空配置。")
        generate_clash_config([], OUTPUT_CLASH_FILE)
        return

    # 阶段3: 统一预筛选
    prefiltered_nodes = prefilter_all_nodes(all_nodes)
    if not prefiltered_nodes:
        logger.warning("预筛选后无节点，切换全量测试。")
        prefiltered_nodes = all_nodes[:]

    # 阶段4: 批量测试延迟
    all_results = test_all_nodes_latency(prefiltered_nodes)

    # 阶段5: 最终处理并生成单一文件
    valid_results = [item for item in all_results if item['latency'] > 0]
    if valid_results:
        valid_results.sort(key=lambda x: x['latency'])
        top_100 = valid_results[:MAX_NODES_LIMIT]
        fast_nodes = []
        for item in top_100:
            node = item['node'].copy()  # 避免修改原node
            latency = item['latency']
            node['name'] = f"{node['name']} | {latency}ms"
            fast_nodes.append(node)
        fast_nodes = ensure_unique_proxy_names(fast_nodes)
        logger.info(f"\n--- 所有处理结束 ---\n最终top {len(fast_nodes)} 个低延迟节点。")
        generate_clash_config(fast_nodes, OUTPUT_CLASH_FILE)
    else:
        logger.warning("无有效低延迟节点，生成空配置。")
        generate_clash_config([], OUTPUT_CLASH_FILE)

    with open(UPDATE_TIME_FILE, 'w', encoding='utf-8') as f:
        update_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        f.write(f"最后更新时间: {update_time}\n可用节点数量: {len(fast_nodes) if 'fast_nodes' in locals() else 0}\n")
    logger.info(f"成功记录更新时间: {UPDATE_TIME_FILE}")

if __name__ == '__main__':
    main()
