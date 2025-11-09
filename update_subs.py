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
from functools import wraps
from dataclasses import dataclass
from typing import List, Dict, Optional, Any
import argparse
import os

try:
    import psutil  # pip install psutil，可选，用于杀进程和内存监控
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    from ping3 import ping  # pip install ping3
    HAS_PING3 = True
except ImportError:
    HAS_PING3 = False
    # Fallback to subprocess ping if needed

import hashlib
from itertools import islice

# --- 配置类 ---
@dataclass
class Config:
    sub_urls_file: str = 'sub_urls.txt'
    output_clash_file: str = 'sub.yaml'
    update_time_file: str = 'update_time.txt'
    clash_binary_path: str = './clash'
    max_latency_ms: int = 500
    max_nodes_limit: int = 100
    real_test_urls: List[str] = None
    api_test_timeout_seconds: int = 10
    ping_threshold_ms: int = 200
    max_retries: int = 3
    batch_size: int = 1000
    prescreen_enabled: bool = True
    debug_mode: bool = True
    max_content_size_mb: int = 10  # 输入验证：订阅内容大小限制

    def __post_init__(self):
        if self.real_test_urls is None:
            self.real_test_urls = [
                'http://cp.cloudflare.com/generate_204',
                'http://www.google.com/generate_204',
                'https://httpbin.org/get'
            ]

# 全局配置实例
config = Config()

# 设置日志
logging.basicConfig(level=logging.INFO if config.debug_mode else logging.WARNING,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def retry(max_retries=config.max_retries, delay=1):
    """重试装饰器"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries - 1:
                        raise
                    logger.debug(f"{func.__name__} 重试 {attempt + 1}/{max_retries}: {e}")
                    time.sleep(delay)
            return None
        return wrapper
    return decorator

def random_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def wait_for_clash_api(api_address, timeout=10):
    api_base = f'http://{api_address}'
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            for endpoint in ['/version', '/traffic']:
                response = requests.get(f'{api_base}{endpoint}', timeout=1)
                if response.status_code == 200:
                    return True
        except:
            pass
        time.sleep(0.2)
    return False

@retry()
def get_subscription_content(url):
    if not url:
        return None
    headers = {'User-Agent': 'Clash/1.11.0'}
    response = requests.get(url, timeout=15, headers=headers)
    response.raise_for_status()
    content = response.text
    if len(content.encode('utf-8')) > config.max_content_size_mb * 1024 * 1024:
        raise ValueError("订阅内容过大")
    response.encoding = 'utf-8'
    logger.info(f"获取订阅成功: {url}")
    return content

def decode_base64_content(content):
    try:
        if len(content) % 4 != 0:
            padding = (4 - len(content) % 4) % 4
            content += '=' * padding
        return base64.b64decode(content.encode('ascii')).decode('utf-8')
    except Exception as e:
        logger.warning(f"Base64解码失败: {e}")
        return None

def key_fields_hash(node):
    """优化去重：仅哈希关键字段"""
    key_str = f"{node.get('type')}_{node.get('server')}_{node.get('port')}_{node.get('uuid', '')}_{node.get('password', '')[:8]}"
    return hashlib.md5(key_str.encode()).hexdigest()

def standardize_node(node: Dict[str, Any]) -> Dict[str, Any]:
    """统一标准化节点"""
    defaults = {'udp': True, 'tls': False, 'skip-cert-verify': False, 'network': 'tcp'}
    for key, value in defaults.items():
        node.setdefault(key, value)
    return node

class NodeParser:
    """节点解析器类，抽象协议解析"""
    def __init__(self):
        self.protocol_map = {
            'ss': self._parse_ss,
            'vmess': self._parse_vmess,
            'trojan': self._parse_trojan,
            'vless': self._parse_vless,
            'hysteria': self._parse_hysteria,
            'hysteria2': self._parse_hysteria2
        }

    def parse(self, link: str) -> Optional[Dict[str, Any]]:
        link = link.strip()
        for prefix, parser in self.protocol_map.items():
            if link.startswith(f"{prefix}://"):
                return parser(link)
        return None

    def _parse_ss(self, ss_link: str) -> Optional[Dict[str, Any]]:
        try:
            parts = urlparse(ss_link)
            if '@' not in parts.netloc:
                logger.warning(f"SS链接格式异常: {ss_link[:50]}...")
                return None
            user_info, host_info = parts.netloc.split('@', 1)
            server, port = host_info.split(':', 1)
            remarks = unquote(parts.fragment) if parts.fragment else f"ss_{server}"
            try:
                user_info_str = base64.urlsafe_b64decode(user_info + '===').decode('utf-8')
            except:
                user_info_str = unquote(user_info)
            method, password = user_info_str.split(':', 1)
            node = {'name': remarks, 'type': 'ss', 'server': server, 'port': int(port),
                    'cipher': method, 'password': password}
            return standardize_node(node)
        except Exception as e:
            logger.warning(f"解析SS失败: {e}")
            return None

    def _parse_vmess(self, vmess_link: str) -> Optional[Dict[str, Any]]:
        try:
            b64_str = vmess_link[8:]
            padding = (4 - len(b64_str) % 4) % 4
            b64_str += '=' * padding
            vmess_data = json.loads(base64.b64decode(b64_str).decode('utf-8'))
            if not all(key in vmess_data for key in ['add', 'port', 'id']):
                return None
            node = {
                'name': vmess_data.get('ps', vmess_data.get('add', '')),
                'type': 'vmess', 'server': vmess_data['add'], 'port': int(vmess_data['port']),
                'uuid': vmess_data['id'], 'alterId': int(vmess_data.get('aid', 0)),
                'cipher': vmess_data.get('scy', 'auto')
            }
            node['tls'] = vmess_data.get('tls') == 'tls'
            if node['tls']:
                node['servername'] = vmess_data.get('sni', vmess_data.get('host', ''))
            node['network'] = vmess_data.get('net', 'tcp')
            if node['network'] == 'ws':
                node['ws-opts'] = {'path': vmess_data.get('path', '/'),
                                   'headers': {'Host': vmess_data.get('host', '')}}
            return standardize_node(node)
        except Exception as e:
            logger.warning(f"解析VMess失败: {e}")
            return None

    def _parse_trojan(self, trojan_link: str) -> Optional[Dict[str, Any]]:
        try:
            parts = urlparse(trojan_link)
            if '@' not in parts.netloc:
                return None
            password, host_info = parts.netloc.split('@', 1)
            server, port = host_info.split(':', 1)
            remarks = unquote(parts.fragment) if parts.fragment else f"trojan_{server}"
            params = {k: v[0] for k, v in parse_qs(parts.query).items()}
            node = {
                'name': remarks, 'type': 'trojan', 'server': server, 'port': int(port),
                'password': password, 'sni': params.get('sni', server),
                'skip-cert-verify': params.get('allowInsecure', '0') in ['1', 'true']
            }
            return standardize_node(node)
        except Exception as e:
            logger.warning(f"解析Trojan失败: {e}")
            return None

    def _parse_vless(self, vless_link: str) -> Optional[Dict[str, Any]]:
        try:
            parts = urlparse(vless_link)
            if '@' not in parts.netloc:
                return None
            uuid, host_info = parts.netloc.split('@', 1)
            server, port = host_info.split(':', 1)
            remarks = unquote(parts.fragment) if parts.fragment else f"vless_{server}"
            params = {k: v[0] for k, v in parse_qs(parts.query).items()}
            node = {
                'name': remarks, 'type': 'vless', 'server': server, 'port': int(port),
                'uuid': uuid, 'network': params.get('type', 'tcp'),
                'servername': params.get('sni', server), 'flow': params.get('flow', '')
            }
            node['tls'] = params.get('security') == 'tls'
            if node['network'] == 'ws':
                node['ws-opts'] = {'path': params.get('path', '/'),
                                   'headers': {'Host': params.get('host', server)}}
            elif node['network'] == 'grpc':
                node['grpc-opts'] = {'grpc-service-name': params.get('serviceName', '')}
            return standardize_node(node)
        except Exception as e:
            logger.warning(f"解析VLESS失败: {e}")
            return None

    def _parse_hysteria(self, hy_link: str) -> Optional[Dict[str, Any]]:
        try:
            parts = urlparse(hy_link)
            netloc = parts.netloc
            if ':' not in netloc:
                return None
            server, port = netloc.split(':', 1)
            remarks = unquote(parts.fragment) if parts.fragment else f"hysteria_{server}"
            params = {k: v[0] for k, v in parse_qs(parts.query).items()}
            node = {
                'name': remarks, 'type': 'hysteria', 'server': server, 'port': int(port),
                'protocol': params.get('protocol', 'udp'), 'auth_str': params.get('auth', ''),
                'up': int(params.get('upmbps', 50)), 'down': int(params.get('downmbps', 100)),
                'sni': params.get('peer', server),
                'skip-cert-verify': params.get('insecure', '0') == '1'
            }
            return standardize_node(node)
        except Exception as e:
            logger.warning(f"解析Hysteria失败: {e}")
            return None

    def _parse_hysteria2(self, hy2_link: str) -> Optional[Dict[str, Any]]:
        try:
            parts = urlparse(hy2_link)
            if '@' not in parts.netloc:
                return None
            password, host_info = parts.netloc.split('@', 1)
            server, port = host_info.split(':', 1)
            remarks = unquote(parts.fragment) if parts.fragment else f"hysteria2_{server}"
            params = {k: v[0] for k, v in parse_qs(parts.query).items()}
            node = {
                'name': remarks, 'type': 'hysteria2', 'server': server, 'port': int(port),
                'password': password, 'sni': params.get('sni', server),
                'skip-cert-verify': params.get('insecure', '0') == '1'
            }
            return standardize_node(node)
        except Exception as e:
            logger.warning(f"解析Hysteria2失败: {e}")
            return None

# 全局解析器实例
node_parser = NodeParser()

def tcp_latency(host: str, port: int, timeout=2) -> int:
    start = time.time()
    try:
        sock = socket.create_connection((host, port), timeout)
        sock.close()
        return round((time.time() - start) * 1000)
    except:
        return -1

def icmp_latency(host: str, timeout=2) -> int:
    if not HAS_PING3:
        # Fallback: subprocess ping (简化实现，实际可扩展)
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', str(timeout * 1000), host],
                                    capture_output=True, text=True, timeout=timeout + 1)
            if result.returncode == 0:
                # 解析时间，简化
                time_line = [line for line in result.stdout.split('\n') if 'time=' in line]
                if time_line:
                    return int(float(time_line[0].split('time=')[1].split(' ')[0]))
        except:
            pass
        return -1
    try:
        delay = ping(host, timeout=timeout)
        return round(delay * 1000) if delay else -1
    except:
        return -1

class ClashProcessManager:
    """Clash进程上下文管理器"""
    def __init__(self, config_path: str, api_address: str):
        self.config_path = config_path
        self.api_address = api_address
        self.process = None

    def __enter__(self):
        command = [config.clash_binary_path, '-f', self.config_path, '-d', '.']
        self.process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not wait_for_clash_api(self.api_address):
            raise RuntimeError("Clash API启动失败")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.process:
            if self.process.poll() is None:
                try:
                    self.process.terminate()
                    self.process.wait(timeout=3)
                except:
                    if HAS_PSUTIL:
                        for child in self.process.children(recursive=True):
                            child.kill()
                        self.process.kill()
                    else:
                        self.process.kill()
            if os.path.exists(self.config_path):
                os.remove(self.config_path)

def test_node_latency_with_shared_clash(api_address: str, node: Dict[str, Any]) -> int:
    """使用共享Clash实例测试单个节点延迟"""
    proxy_name_for_api = requests.utils.quote(node['name'])
    delays = []
    for _ in range(config.max_retries):
        for test_url in config.real_test_urls:
            api_url = f'http://{api_address}/proxies/{proxy_name_for_api}/delay'
            params = {'url': test_url, 'timeout': int(config.api_test_timeout_seconds * 1000)}
            try:
                response = requests.get(api_url, params=params, timeout=config.api_test_timeout_seconds + 2)
                response.raise_for_status()
                delay_data = response.json()
                delay = delay_data.get('delay', -1)
                if delay > 0:
                    delays.append(delay)
            except Exception as e:
                logger.debug(f"API测试失败 {test_url} for {node['name']}: {e}")
        if delays:
            break
        time.sleep(1)
    avg_delay = sum(delays) / len(delays) if delays else -1
    return round(avg_delay) if avg_delay > 0 else -1

def test_nodes_with_shared_clash(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """使用共享Clash实例批量测试节点延迟，避免生成临时单节点配置"""
    if not nodes:
        return []

    rand_id = random_string()
    temp_config_path = f'temp_batch_config_{rand_id}.yaml'
    api_port = get_free_port()
    api_address = f'127.0.0.1:{api_port}'
    proxy_names = [node['name'] for node in nodes]

    config_dict = {
        'proxies': nodes,
        'proxy-groups': [
            {'name': 'test-group', 'type': 'select', 'proxies': proxy_names}
        ],
        'unified-delay': True,
        'external-controller': api_address,
        'log-level': 'silent',
        'port': get_free_port(),
        'socks-port': get_free_port(),
        'mixed-port': get_free_port()
    }
    with open(temp_config_path, 'w', encoding='utf-8') as f:
        yaml.dump(config_dict, f)

    try:
        with ClashProcessManager(temp_config_path, api_address):
            max_workers = min(os.cpu_count() or 8, len(nodes))
            this_results = []
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(test_node_latency_with_shared_clash, api_address, node): node for node in nodes}
                for future in tqdm(as_completed(futures), total=len(nodes), desc="批量Clash测试"):
                    node = futures[future]
                    try:
                        latency = future.result()
                        if 0 < latency < config.max_latency_ms:
                            this_results.append({'node': node, 'latency': latency})
                            logger.info(f"批量测试成功 {node['name']}: {latency}ms")
                        else:
                            logger.warning(f"批量测试失败 {node['name']}: {latency}ms")
                    except Exception as e:
                        logger.error(f"批量测试异常 {node['name']}: {e}")
            return this_results
    except Exception as e:
        logger.error(f"批量Clash测试错误: {e}")
        return []

def ensure_unique_proxy_names(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    name_counts = {}
    for node in nodes:
        name = node['name']
        if name in name_counts:
            name_counts[name] += 1
            node['name'] = f"{name}_{random_string(4)}"  # 更描述性后缀
        else:
            name_counts[name] = 1
    return nodes

def chunks(iterable, size):
    iterator = iter(iterable)
    for first in iterator:
        yield list(islice(iterator, size - 1, None)) + [first] if size > 1 else [first]

def dynamic_batch_size(base_size: int = 1000) -> int:
    """动态批次大小基于内存"""
    if HAS_PSUTIL:
        memory = psutil.virtual_memory()
        available_gb = memory.available / (1024 ** 3)
        return min(base_size, max(100, int(available_gb * 500)))  # 粗略估计
    return base_size

def generate_clash_config(fast_nodes: List[Dict[str, Any]], output_filename: str, yaml_cache: Optional[Dict] = None):
    logger.info(f"生成Clash配置: {len(fast_nodes)} 个节点 -> {output_filename}")
    
    # 验证节点
    invalid_nodes = [node for node in fast_nodes if not all(key in node for key in ['name', 'type', 'server', 'port'])]
    fast_nodes = [node for node in fast_nodes if all(key in node for key in ['name', 'type', 'server', 'port'])]
    if invalid_nodes:
        logger.warning(f"移除 {len(invalid_nodes)} 个无效节点")

    if not fast_nodes:
        logger.warning(f"无可用节点，生成空配置")

    proxy_names = [node['name'] for node in fast_nodes]
    clash_config = {
        'port': 7890, 'socks-port': 7891, 'allow-lan': False, 'mode': 'rule',
        'log-level': 'info', 'external-controller': '127.0.0.1:9090', 'unified-delay': True,
        'dns': {
            'enabled': True, 'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16',
            'nameserver': ['https://doh.pub/dns-query', 'https://223.5.5.5/dns-query'],
            'fallback': ['8.8.8.8', '1.1.1.1', 'tls://dns.google:853']
        },
        'proxies': fast_nodes,
        'proxy-groups': [
            {'name': 'PROXY', 'type': 'select', 'proxies': ['AUTO-URL', 'DIRECT'] + proxy_names},
            {'name': 'AUTO-URL', 'type': 'url-test', 'proxies': proxy_names,
             'url': 'http://cp.cloudflare.com/generate_204', 'interval': 300}
        ],
        'rules': ['GEOIP,CN,DIRECT', 'MATCH,PROXY']
    }
    
    try:
        with open(output_filename, 'w', encoding='utf-8') as f:
            yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
        logger.info(f"Clash配置生成成功: {output_filename}")
        return clash_config  # 返回缓存
    except Exception as e:
        logger.error(f"写入YAML失败: {e}")
        return yaml_cache  # 回退缓存

def process_subscription(url: str, unique_nodes_set: set, global_valid_results: List[Dict[str, Any]],
                         yaml_cache: Dict[str, Any]) -> List[Dict[str, Any]]:
    """处理单个订阅，返回有效节点列表"""
    logger.info(f"处理订阅: {url}")
    content = get_subscription_content(url)
    if not content:
        logger.warning(f"订阅获取失败: {url}")
        return []

    this_all_nodes = []
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict) and 'proxies' in data and isinstance(data['proxies'], list):
            for proxy in data['proxies']:
                if all(k in proxy for k in ['name', 'server', 'port', 'type']):
                    node = standardize_node(proxy)
                    node_hash_val = key_fields_hash(node)
                    if node_hash_val not in unique_nodes_set:
                        this_all_nodes.append(node)
                        unique_nodes_set.add(node_hash_val)
            if config.debug_mode:
                logger.info(f"YAML解析: {len(this_all_nodes)} 个节点")
    except Exception as e:
        logger.debug(f"YAML解析失败: {e}")

    if not this_all_nodes:
        decoded = decode_base64_content(content)
        links_content = decoded if decoded else content
        for link in links_content.splitlines():
            node = node_parser.parse(link)
            if node:
                node_hash_val = key_fields_hash(node)
                if node_hash_val not in unique_nodes_set:
                    this_all_nodes.append(node)
                    unique_nodes_set.add(node_hash_val)
        if config.debug_mode:
            logger.info(f"链接解析: {len(this_all_nodes)} 个节点")

    if not this_all_nodes:
        logger.warning(f"订阅无有效节点: {url}")
        return []

    # 预筛选
    this_prefiltered_nodes = this_all_nodes[:]
    if config.prescreen_enabled:
        logger.info("预筛选节点...")
        this_prefiltered_nodes = []
        failed_count = 0
        max_workers_pre = min(os.cpu_count() or 4, len(this_all_nodes))
        with ThreadPoolExecutor(max_workers=max_workers_pre) as executor:
            futures = {executor.submit(lambda n: (icmp_latency(n['server']) <= config.ping_threshold_ms and icmp_latency(n['server']) != -1) and tcp_latency(n['server'], n['port']) > 0 and tcp_latency(n['server'], n['port']) < config.max_latency_ms * 2, node): node for node in this_all_nodes}
            for future in as_completed(futures):
                node = futures[future]
                try:
                    if future.result():
                        this_prefiltered_nodes.append(node)
                    else:
                        failed_count += 1
                except:
                    failed_count += 1
        logger.info(f"预筛选后: {len(this_prefiltered_nodes)} / {len(this_all_nodes)}")

    if len(this_prefiltered_nodes) == 0:
        logger.warning(f"预筛选全失败，切换全量测试: {len(this_all_nodes)} 个")
        this_prefiltered_nodes = this_all_nodes[:]

    # 批量Clash测试：使用共享配置测试所有节点，避免单节点临时文件
    logger.info(f"批量Clash测试: {len(this_prefiltered_nodes)} 个节点")
    this_results = test_nodes_with_shared_clash(this_prefiltered_nodes)

    valid_this = [item for item in this_results if item['latency'] > 0]
    global_valid_results.extend(valid_this)
    logger.info(f"追加 {len(valid_this)} 个有效节点，全局 {len(global_valid_results)} 个")

    # 实时更新配置
    if global_valid_results:
        global_valid_results.sort(key=lambda x: x['latency'])
        top_n = global_valid_results[:config.max_nodes_limit]
        fast_nodes = []
        for item in top_n:
            item_node = item['node'].copy()
            item_node['name'] = f"{item_node['name']} | {item['latency']}ms"
            fast_nodes.append(item_node)
        fast_nodes = ensure_unique_proxy_names(fast_nodes)
        yaml_cache = generate_clash_config(fast_nodes, config.output_clash_file, yaml_cache)

    return valid_this

def main():
    parser = argparse.ArgumentParser(description="Clash订阅优化工具")
    parser.add_argument('--max-latency', type=int, default=config.max_latency_ms, help='最大延迟 (ms)')
    parser.add_argument('--max-nodes', type=int, default=config.max_nodes_limit, help='最大节点数')
    parser.add_argument('--no-prescreen', action='store_true', help='禁用预筛选')
    parser.add_argument('--debug', action='store_true', help='启用调试模式')
    parser.add_argument('--clash-path', default=config.clash_binary_path, help='Clash二进制路径')
    args = parser.parse_args()

    config.max_latency_ms = args.max_latency
    config.max_nodes_limit = args.max_nodes
    config.prescreen_enabled = not args.no_prescreen
    config.debug_mode = args.debug
    config.clash_binary_path = args.clash_path

    logging.getLogger().setLevel(logging.DEBUG if config.debug_mode else logging.INFO)

    if not os.path.exists(config.clash_binary_path):
        logger.error(f"Clash未找到: {config.clash_binary_path}")
        sys.exit(1)

    if not os.path.exists(config.sub_urls_file):
        logger.error(f"订阅文件不存在: {config.sub_urls_file}")
        with open(config.sub_urls_file, 'w', encoding='utf-8') as f:
            f.write("# 粘贴订阅链接\n")
        return

    with open(config.sub_urls_file, 'r', encoding='utf-8') as f:
        subscription_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    if not subscription_urls:
        logger.warning("无有效订阅链接")
        return

    logger.info(f"开始处理 {len(subscription_urls)} 个订阅")

    global_valid_results = []
    unique_nodes_set = set()
    yaml_cache = {}  # 初始空缓存

    # 初始空配置
    generate_clash_config([], config.output_clash_file, yaml_cache)

    failed_count = 0
    for idx, url in enumerate(subscription_urls, 1):
        logger.info(f"\n--- 第 {idx}/{len(subscription_urls)}: {url} ---")
        try:
            process_subscription(url, unique_nodes_set, global_valid_results, yaml_cache)
        except Exception as e:
            logger.error(f"订阅处理失败 {url}: {e}")
            failed_count += 1

    if failed_count > len(subscription_urls) * 0.5:
        logger.warning("订阅失败率高 (>50%)，建议检查网络")

    # 最终配置
    if global_valid_results:
        global_valid_results.sort(key=lambda x: x['latency'])
        top_n = global_valid_results[:config.max_nodes_limit]
        fast_nodes = []
        for item in top_n:
            item_node = item['node'].copy()
            item_node['name'] = f"{item_node['name']} | {item['latency']}ms"
            fast_nodes.append(item_node)
        fast_nodes = ensure_unique_proxy_names(fast_nodes)
        logger.info(f"最终top {len(fast_nodes)} 个节点")
        yaml_cache = generate_clash_config(fast_nodes, config.output_clash_file, yaml_cache)
    else:
        logger.warning("无有效节点")
        generate_clash_config([], config.output_clash_file, yaml_cache)

    with open(config.update_time_file, 'w', encoding='utf-8') as f:
        update_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        f.write(f"最后更新: {update_time}\n可用节点: {len(fast_nodes) if 'fast_nodes' in locals() else 0}\n")
    logger.info(f"更新完成: {config.update_time_file}")

if __name__ == '__main__':
    main()
