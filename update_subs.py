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

# ==================== 全局配置 ====================
SUBSCRIPTION_URLS_FILE = 'sub_urls.txt'
OUTPUT_CLASH_FILE = 'sub.yaml'
UPDATE_TIME_FILE = 'update_time.txt'
MAX_LATENCY_MS = 500
MAX_NODES_LIMIT = 200

# 谷歌学术专用测试配置
REAL_TEST_URLS = [
    'https://scholar.google.com/robots.txt',      # 快速连通性测试
    'https://www.google.com/generate_204',        # 基础连接测试
    'http://www.gstatic.com/generate_204'         # 备用测试
]

# 学术访问验证配置
SCHOLAR_VERIFY_URL = 'https://scholar.google.com/scholar?q=machine+learning'
SCHOLAR_KEYWORDS = ['scholar', 'articles', 'cited by', 'search']
SCHOLAR_TEST_ENABLED = True  # 是否启用学术访问验证

API_TEST_TIMEOUT_SECONDS = 12  # 延长超时
PING_THRESHOLD_MS = 200  # 预筛选阈值
MAX_RETRIES = 3  # API重试次数
BATCH_SIZE = 1000  # 分批大小
PRESCREEN_ENABLED = True  # 可设为 False 禁用预筛选
DEBUG_MODE = True  # 启用详细日志

# 并发控制配置（避免触发Google限流）
MAX_WORKERS_FETCH = 5  # 订阅获取并发数
MAX_WORKERS_TEST = 4   # 节点测试并发数（降低以避免被限流）
REQUEST_INTERVAL_MIN = 0.5  # 最小请求间隔(秒)
REQUEST_INTERVAL_MAX = 1.2  # 最大请求间隔(秒)

CLASH_BINARY_PATH = './clash'

# ==================== 日志配置 ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('clash_test.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

# ==================== 工具函数 ====================
def random_string(length=8):
    """生成随机字符串"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def get_free_port():
    """获取空闲端口"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def wait_for_clash_api(api_address, timeout=12):
    """等待Clash API就绪"""
    api_base = f'http://{api_address}'
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            for endpoint in ['/version', '/']:
                try:
                    response = requests.get(f'{api_base}{endpoint}', timeout=1)
                    if response.status_code == 200:
                        return True
                except:
                    pass
        except:
            pass
        time.sleep(0.3)
    return False

def node_hash(node):
    """生成节点哈希用于去重"""
    key = f"{node.get('type')}:{node.get('server')}:{node.get('port')}:{node.get('uuid', node.get('password', ''))}"
    return hashlib.md5(key.encode()).hexdigest()

def standardize_node(node):
    """标准化节点，添加默认字段"""
    defaults = {'udp': True, 'skip-cert-verify': False}
    for key, value in defaults.items():
        node.setdefault(key, value)
    return node

# ==================== 订阅获取 ====================
def get_subscription_content(url):
    """获取订阅内容"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    try:
        logger.info(f"获取订阅: {url[:60]}...")
        response = requests.get(url, timeout=20, headers=headers)
        response.raise_for_status()
        response.encoding = 'utf-8'
        return response.text
    except requests.RequestException as e:
        logger.error(f"获取订阅失败: {url[:60]}, 错误: {e}")
        return None

def decode_base64_content(content):
    """Base64解码"""
    try:
        if len(content) % 4 != 0:
            padding = (4 - len(content) % 4) % 4
            content += '=' * padding
        return base64.b64decode(content.encode('ascii')).decode('utf-8')
    except Exception as e:
        logger.debug(f"Base64解码失败: {e}")
        return None

# ==================== 节点解析函数 ====================
def parse_node(link):
    """统一节点解析入口"""
    link = link.strip()
    if link.startswith('ss://'): return parse_ss_link(link)
    elif link.startswith('vmess://'): return parse_vmess_link(link)
    elif link.startswith('trojan://'): return parse_trojan_link(link)
    elif link.startswith('vless://'): return parse_vless_link(link)
    elif link.startswith('hysteria://'): return parse_hysteria_link(link)
    elif link.startswith('hysteria2://'): return parse_hysteria2_link(link)
    return None

def parse_ss_link(ss_link):
    """解析Shadowsocks链接"""
    try:
        parts = urlparse(ss_link)
        if '@' not in parts.netloc:
            return None
        user_info, host_info = parts.netloc.split('@', 1)
        server, port = host_info.rsplit(':', 1)
        remarks = unquote(parts.fragment) if parts.fragment else f"ss_{server}"
        try:
            user_info_str = base64.urlsafe_b64decode(user_info + '===').decode('utf-8')
        except:
            user_info_str = unquote(user_info)
        method, password = user_info_str.split(':', 1)
        node = {
            'name': remarks,
            'type': 'ss',
            'server': server,
            'port': int(port),
            'cipher': method,
            'password': password
        }
        return standardize_node(node)
    except Exception as e:
        logger.debug(f"解析SS失败: {e}")
        return None

def parse_vmess_link(vmess_link):
    """解析VMess链接"""
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
            node['ws-opts'] = {
                'path': vmess_data.get('path', '/'),
                'headers': {'Host': vmess_data.get('host', '')}
            }
        return standardize_node(node)
    except Exception as e:
        logger.debug(f"解析VMess失败: {e}")
        return None

def parse_trojan_link(trojan_link):
    """解析Trojan链接"""
    try:
        parts = urlparse(trojan_link)
        if '@' not in parts.netloc:
            return None
        password, host_info = parts.netloc.split('@', 1)
        server, port = host_info.rsplit(':', 1)
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
        logger.debug(f"解析Trojan失败: {e}")
        return None

def parse_vless_link(vless_link):
    """解析VLESS链接"""
    try:
        parts = urlparse(vless_link)
        if '@' not in parts.netloc:
            return None
        uuid, host_info = parts.netloc.split('@', 1)
        server, port = host_info.rsplit(':', 1)
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
            node['ws-opts'] = {
                'path': params.get('path', '/'),
                'headers': {'Host': params.get('host', server)}
            }
        elif node['network'] == 'grpc':
            node['grpc-opts'] = {'grpc-service-name': params.get('serviceName', '')}
        return standardize_node(node)
    except Exception as e:
        logger.debug(f"解析VLESS失败: {e}")
        return None

def parse_hysteria_link(hy_link):
    """解析Hysteria链接"""
    try:
        parts = urlparse(hy_link)
        netloc = parts.netloc
        if ':' not in netloc:
            return None
        server, port = netloc.rsplit(':', 1)
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
        logger.debug(f"解析Hysteria失败: {e}")
        return None

def parse_hysteria2_link(hy2_link):
    """解析Hysteria2链接"""
    try:
        parts = urlparse(hy2_link)
        if '@' not in parts.netloc:
            return None
        password, host_info = parts.netloc.split('@', 1)
        server, port = host_info.rsplit(':', 1)
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
        logger.debug(f"解析Hysteria2失败: {e}")
        return None

# ==================== 预筛选函数 ====================
def tcp_latency(host, port, timeout=2):
    """TCP握手延迟测试"""
    start = time.time()
    try:
        sock = socket.create_connection((host, port), timeout)
        sock.close()
        return round((time.time() - start) * 1000)
    except:
        return -1

def icmp_latency(host, timeout=2):
    """ICMP ping延迟测试"""
    try:
        delay = ping(host, timeout=timeout, unit='ms')
        return round(delay) if delay else -1
    except:
        return -1

# ==================== Clash进程管理 ====================
def kill_clash_process(process):
    """安全终止Clash进程"""
    if process and process.poll() is None:
        try:
            process.terminate()
            process.wait(timeout=3)
        except:
            try:
                if HAS_PSUTIL:
                    parent = psutil.Process(process.pid)
                    for child in parent.children(recursive=True):
                        child.kill()
                process.kill()
            except:
                pass

# ==================== 谷歌学术访问验证 ====================
def verify_scholar_access(proxy_address, node_name, timeout=15):
    """验证节点是否可访问Google Scholar"""
    if not SCHOLAR_TEST_ENABLED:
        return True

    try:
        # 通过SOCKS5代理测试
        proxies = {
            'http': f'socks5h://{proxy_address}',
            'https': f'socks5h://{proxy_address}'
        }

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br'
        }

        response = requests.get(
            SCHOLAR_VERIFY_URL,
            proxies=proxies,
            timeout=timeout,
            headers=headers,
            verify=False
        )

        if response.status_code == 200:
            content_lower = response.text.lower()
            # 检查是否包含学术页面特征
            has_scholar_content = any(kw in content_lower for kw in SCHOLAR_KEYWORDS)
            # 检查是否被CAPTCHA拦截
            is_blocked = any(block_kw in content_lower for block_kw in ['captcha', 'automated queries', 'unusual traffic'])

            if has_scholar_content and not is_blocked:
                logger.info(f"✓ {node_name}: Google Scholar可访问")
                return True
            elif is_blocked:
                logger.warning(f"✗ {node_name}: 被Google Scholar拦截(CAPTCHA)")
                return False

        logger.warning(f"✗ {node_name}: Google Scholar不可访问(状态码: {response.status_code})")
        return False

    except Exception as e:
        logger.debug(f"学术访问验证失败 {node_name}: {e}")
        return False

# ==================== 节点延迟测试（核心函数）====================
def test_node_latency_with_clash_core(node):
    """使用Clash核心测试节点延迟并验证Google Scholar访问"""
    rand_id = random_string()
    temp_config_path = f'temp_config_{rand_id}.yaml'
    api_port = get_free_port()
    socks_port = get_free_port()
    mixed_port = get_free_port()
    api_address = f'127.0.0.1:{api_port}'
    proxy_address = f'127.0.0.1:{socks_port}'

    # URL编码节点名
    try:
        proxy_name_for_api = requests.utils.quote(node['name'])
    except:
        proxy_name_for_api = node['name']

    # 构建Clash配置
    config = {
        'proxies': [node],
        'proxy-groups': [{
            'name': 'test-group',
            'type': 'select',
            'proxies': [node['name']]
        }],
        'external-controller': api_address,
        'log-level': 'silent',
        'socks-port': socks_port,
        'mixed-port': mixed_port,
        'allow-lan': False
    }

    try:
        with open(temp_config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True)
    except Exception as e:
        logger.error(f"写入配置失败 {node['name']}: {e}")
        return -1

    process = None
    try:
        # 启动Clash进程
        command = [CLASH_BINARY_PATH, '-f', temp_config_path, '-d', '.']
        process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL
        )

        # 等待API就绪
        if not wait_for_clash_api(api_address, timeout=12):
            logger.warning(f"Clash API启动失败: {node['name']}")
            return -1

        # 检查进程状态
        if process.poll() is not None:
            logger.warning(f"Clash进程异常退出: {node['name']}")
            return -1

        # 第一阶段：基础延迟测试
        delays = []
        for attempt in range(MAX_RETRIES):
            for test_url in REAL_TEST_URLS:
                api_url = f'http://{api_address}/proxies/{proxy_name_for_api}/delay'
                params = {
                    'url': test_url,
                    'timeout': int(API_TEST_TIMEOUT_SECONDS * 1000)
                }
                try:
                    response = requests.get(
                        api_url,
                        params=params,
                        timeout=API_TEST_TIMEOUT_SECONDS + 3
                    )
                    if response.status_code == 200:
                        delay_data = response.json()
                        delay = delay_data.get('delay', -1)
                        if delay > 0:
                            delays.append(delay)
                            logger.debug(f"{node['name']}: {test_url} = {delay}ms")
                            break  # 成功后跳出URL循环
                except Exception as e:
                    logger.debug(f"API测试失败 {test_url}: {e}")

            if delays:
                break

            # 重试间隔
            if attempt < MAX_RETRIES - 1:
                time.sleep(1)

        if not delays:
            logger.warning(f"✗ {node['name']}: 延迟测试全部失败")
            return -1

        avg_delay = sum(delays) / len(delays)

        # 第二阶段：Google Scholar访问验证（仅对低延迟节点）
        if avg_delay < MAX_LATENCY_MS:
            # 添加随机延迟，避免触发限流
            time.sleep(random.uniform(REQUEST_INTERVAL_MIN, REQUEST_INTERVAL_MAX))

            scholar_ok = verify_scholar_access(proxy_address, node['name'])
            if not scholar_ok:
                logger.warning(f"✗ {node['name']}: 延迟{round(avg_delay)}ms但Google Scholar不可访问")
                return -1

        final_delay = round(avg_delay)
        logger.info(f"✓ {node['name']}: {final_delay}ms (Scholar可访问)")
        return final_delay

    except Exception as e:
        logger.error(f"节点测试异常 {node['name']}: {e}")
        return -1
    finally:
        # 清理资源
        if process:
            kill_clash_process(process)
        time.sleep(0.2)  # 确保端口释放
        try:
            if os.path.exists(temp_config_path):
                os.remove(temp_config_path)
        except:
            pass

def test_with_backoff(node, max_attempts=2):
    """带指数退避的测试"""
    for attempt in range(max_attempts):
        result = test_node_latency_with_clash_core(node)
        if result > 0:
            return result

        if attempt < max_attempts - 1:
            wait_time = (2 ** attempt) + random.uniform(0, 1)
            logger.debug(f"重试 {node['name']}, 等待 {wait_time:.1f}秒")
            time.sleep(wait_time)

    return -1

# ==================== 节点处理流程 ====================
def parse_all_nodes(all_contents):
    """统一解析所有订阅节点"""
    all_nodes = []
    unique_nodes_set = set()

    for url, content in all_contents.items():
        this_nodes = []

        # 先尝试YAML解析
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict) and 'proxies' in data:
                for proxy in data['proxies']:
                    if all(k in proxy for k in ['name', 'server', 'port', 'type']):
                        node = standardize_node(proxy)
                        node_hash_val = node_hash(node)
                        if node_hash_val not in unique_nodes_set:
                            node['source'] = url[:60]
                            this_nodes.append(node)
                            unique_nodes_set.add(node_hash_val)
                if this_nodes:
                    logger.info(f"YAML订阅解析出 {len(this_nodes)} 个节点")
        except Exception as e:
            logger.debug(f"YAML解析失败: {e}")

        # Fallback: Base64/链接解析
        if not this_nodes:
            decoded_content = decode_base64_content(content)
            links_content = decoded_content if decoded_content else content
            for link in links_content.splitlines():
                node = parse_node(link)
                if node:
                    node_hash_val = node_hash(node)
                    if node_hash_val not in unique_nodes_set:
                        node['source'] = url[:60]
                        this_nodes.append(node)
                        unique_nodes_set.add(node_hash_val)
            if this_nodes:
                logger.info(f"链接订阅解析出 {len(this_nodes)} 个节点")

        all_nodes.extend(this_nodes)

    logger.info(f"总解析 {len(all_nodes)} 个唯一节点（全局去重）")
    return all_nodes

def prefilter_all_nodes(all_nodes):
    """统一预筛选所有节点"""
    if not PRESCREEN_ENABLED:
        return all_nodes[:]

    logger.info(f"开始预筛选 {len(all_nodes)} 个节点...")
    prefiltered_nodes = []

    for node in tqdm(all_nodes, desc="预筛选"):
        # ICMP测试
        icmp = icmp_latency(node['server'], timeout=2)
        if icmp > 0 and icmp < PING_THRESHOLD_MS:
            # TCP测试
            tcp = tcp_latency(node['server'], node['port'], timeout=2)
            if tcp > 0 and tcp < MAX_LATENCY_MS * 2:
                prefiltered_nodes.append(node)
                logger.debug(f"预筛选通过 {node['name']}: ping={icmp}ms, tcp={tcp}ms")

    logger.info(f"预筛选后剩余 {len(prefiltered_nodes)} 个节点")
    return prefiltered_nodes

def test_all_nodes_latency(prefiltered_nodes):
    """批量测试所有预筛选节点延迟"""
    all_results = []
    max_workers = min(MAX_WORKERS_TEST, len(prefiltered_nodes))

    logger.info(f"开始Clash测试 {len(prefiltered_nodes)} 个节点 (并发数: {max_workers})...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_node = {
            executor.submit(test_with_backoff, node): node
            for node in prefiltered_nodes
        }

        for future in tqdm(as_completed(future_to_node), total=len(prefiltered_nodes), desc="学术访问测试"):
            node = future_to_node[future]
            try:
                latency = future.result(timeout=90)
                if 0 < latency < MAX_LATENCY_MS:
                    all_results.append({'node': node, 'latency': latency})
            except concurrent.futures.TimeoutError:
                logger.warning(f"✗ {node['name']}: 测试超时")
            except Exception as e:
                logger.error(f"✗ {node['name']}: {e}")

            # 添加随机间隔，避免被限流
            time.sleep(random.uniform(REQUEST_INTERVAL_MIN, REQUEST_INTERVAL_MAX))

    logger.info(f"测试完成，{len(all_results)}/{len(prefiltered_nodes)} 个节点可用")
    return all_results

def ensure_unique_proxy_names(nodes):
    """确保节点名称唯一"""
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
    """生成Clash配置文件"""
    logger.info(f"生成配置文件: {len(fast_nodes)} 个节点 -> {output_filename}")

    # 验证节点完整性
    valid_nodes = []
    for node in fast_nodes:
        if all(key in node for key in ['name', 'type', 'server', 'port']):
            # 移除内部标记字段
            node.pop('source', None)
            valid_nodes.append(node)

    clash_config = {
        'port': 7890,
        'socks-port': 7891,
        'allow-lan': False,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'dns': {
            'enabled': True,
            'enhanced-mode': 'fake-ip',
            'fake-ip-range': '198.18.0.1/16',
            'nameserver': ['https://doh.pub/dns-query', 'https://223.5.5.5/dns-query'],
            'fallback': ['8.8.8.8', '1.1.1.1']
        },
        'proxies': valid_nodes
    }

    proxy_names = [node['name'] for node in valid_nodes]

    if proxy_names:
        clash_config['proxy-groups'] = [
            {
                'name': 'PROXY',
                'type': 'select',
                'proxies': ['AUTO', 'DIRECT'] + proxy_names
            },
            {
                'name': 'AUTO',
                'type': 'url-test',
                'proxies': proxy_names,
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300,
                'tolerance': 50
            }
        ]
    else:
        clash_config['proxy-groups'] = [
            {'name': 'PROXY', 'type': 'select', 'proxies': ['DIRECT']}
        ]

    clash_config['rules'] = [
        'DOMAIN-SUFFIX,scholar.google.com,PROXY',
        'DOMAIN-SUFFIX,google.com,PROXY',
        'GEOIP,CN,DIRECT',
        'MATCH,PROXY'
    ]

    try:
        with open(output_filename, 'w', encoding='utf-8') as f:
            yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
        logger.info(f"✓ 成功生成配置文件: {output_filename} ({len(valid_nodes)} 个节点)")
    except Exception as e:
        logger.error(f"写入配置文件失败: {e}")

# ==================== 主函数 ====================
def main():
    """主流程"""
    logger.info("="*60)
    logger.info("Clash节点测试工具 - Google Scholar专用版")
    logger.info("="*60)

    # 检查Clash核心
    if not os.path.exists(CLASH_BINARY_PATH):
        logger.error(f"Clash核心文件未找到: {CLASH_BINARY_PATH}")
        logger.error("请下载Clash核心并放置在脚本同目录下")
        sys.exit(1)

    # 检查订阅文件
    if not os.path.exists(SUBSCRIPTION_URLS_FILE):
        logger.error(f"订阅文件不存在: {SUBSCRIPTION_URLS_FILE}")
        with open(SUBSCRIPTION_URLS_FILE, 'w', encoding='utf-8') as f:
            f.write("# 在这里粘贴你的订阅链接，每行一个\n")
            f.write("# 示例：https://example.com/sub?token=xxx\n")
        logger.info(f"已创建模板文件: {SUBSCRIPTION_URLS_FILE}")
        return

    # 读取订阅链接
    with open(SUBSCRIPTION_URLS_FILE, 'r', encoding='utf-8') as f:
        subscription_urls = [
            line.strip() for line in f
            if line.strip() and not line.startswith('#')
        ]

    if not subscription_urls:
        logger.warning("订阅文件中没有有效链接")
        generate_clash_config([], OUTPUT_CLASH_FILE)
        return

    logger.info(f"找到 {len(subscription_urls)} 个订阅链接")

    # 阶段1: 并发获取订阅内容
    logger.info("\n[阶段1/5] 获取订阅内容...")
    all_contents = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_FETCH) as executor:
        future_to_url = {
            executor.submit(get_subscription_content, url): url
            for url in subscription_urls
        }
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            content = future.result()
            if content:
                all_contents[url] = content

    if not all_contents:
        logger.warning("所有订阅获取失败")
        generate_clash_config([], OUTPUT_CLASH_FILE)
        return

    logger.info(f"成功获取 {len(all_contents)}/{len(subscription_urls)} 个订阅")

    # 阶段2: 解析节点
    logger.info("\n[阶段2/5] 解析节点...")
    all_nodes = parse_all_nodes(all_contents)
    if not all_nodes:
        logger.warning("未解析到有效节点")
        generate_clash_config([], OUTPUT_CLASH_FILE)
        return

    # 阶段3: 预筛选
    logger.info("\n[阶段3/5] 预筛选节点...")
    prefiltered_nodes = prefilter_all_nodes(all_nodes)
    if not prefiltered_nodes:
        logger.warning("预筛选后无节点，使用全部节点测试")
        # prefiltered_nodes = all_nodes[:min(len(all_nodes), 100)]  # 限制数量
        prefiltered_nodes = all_nodes

    # 阶段4: Clash延迟测试 + Google Scholar验证
    logger.info("\n[阶段4/5] Clash延迟测试 + Google Scholar访问验证...")
    all_results = test_all_nodes_latency(prefiltered_nodes)

    # 阶段5: 生成配置文件
    logger.info("\n[阶段5/5] 生成配置文件...")
    valid_results = [item for item in all_results if item['latency'] > 0]

    if valid_results:
        # 按延迟排序
        valid_results.sort(key=lambda x: x['latency'])
        top_nodes = valid_results[:MAX_NODES_LIMIT]

        fast_nodes = []
        for item in top_nodes:
            node = item['node'].copy()
            latency = item['latency']
            node['name'] = f"{node['name']} | {latency}ms"
            fast_nodes.append(node)

        fast_nodes = ensure_unique_proxy_names(fast_nodes)
        generate_clash_config(fast_nodes, OUTPUT_CLASH_FILE)

        logger.info("\n" + "="*60)
        logger.info(f"✓ 处理完成！共筛选出 {len(fast_nodes)} 个可用节点")
        logger.info(f"✓ 配置文件: {OUTPUT_CLASH_FILE}")
        logger.info("="*60)
    else:
        logger.warning("无可用节点，生成空配置")
        generate_clash_config([], OUTPUT_CLASH_FILE)

    # 记录更新时间
    try:
        with open(UPDATE_TIME_FILE, 'w', encoding='utf-8') as f:
            update_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            node_count = len(fast_nodes) if 'fast_nodes' in locals() else 0
            f.write(f"最后更新时间: {update_time}\n")
            f.write(f"可用节点数量: {node_count}\n")
            f.write(f"订阅来源数量: {len(all_contents)}\n")
        logger.info(f"✓ 更新时间已记录: {UPDATE_TIME_FILE}")
    except Exception as e:
        logger.error(f"记录更新时间失败: {e}")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\n用户中断执行")
        sys.exit(0)
    except Exception as e:
        logger.error(f"程序异常: {e}", exc_info=True)
        sys.exit(1)
