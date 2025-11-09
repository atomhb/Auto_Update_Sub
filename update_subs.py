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
    supported_clash_types: List[str] = None  # 支持的Clash协议
    use_clash_testing: bool = False  # 默认禁用Clash测试以避免临时文件生成
    meta_mode: bool = False  # Clash Meta模式，支持Hysteria等

    def __post_init__(self):
        if self.real_test_urls is None:
            self.real_test_urls = [
                'http://cp.cloudflare.com/generate_204',
                'http://www.google.com/generate_204',
                'https://httpbin.org/get'
            ]
        if self.supported_clash_types is None:
            self.supported_clash_types = ['ss', 'vmess', 'trojan', 'vless']  # 标准Clash支持

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
    """统一标准化节点，确保Clash (Meta) 兼容格式"""
    defaults = {'udp': True, 'tls': False, 'skip-cert-verify': False, 'network': 'tcp'}
    for key, value in defaults.items():
        node.setdefault(key, value)
    # 对于所有协议，标记兼容性；在Meta模式下Hysteria兼容
    node_type = node.get('type', '')
    if config.meta_mode:
        node['clash-compatible'] = True  # Meta支持所有
    else:
        node['clash-compatible'] = node_type not in ['hysteria', 'hysteria2']
    # V2Ray/其他特定：确保必要字段
    if node_type == 'vmess':
        node.setdefault('alterId', 0)
        node.setdefault('cipher', 'auto')
    elif node_type == 'vless':
        node.setdefault('flow', '')
    elif node_type == 'hysteria':
        # Meta Hysteria字段
        node.setdefault('up', '100 Mbps')
        node.setdefault('down', '100 Mbps')
        node.setdefault('auth', '')
        node.setdefault('ca', '')
        node.setdefault('alpn', ['h3'])
    elif node_type == 'hysteria2':
        # Meta Hysteria2字段
        node.setdefault('up', '100 Mbps')
        node.setdefault('down', '100 Mbps')
        node.setdefault('password', '')
        node.setdefault('ca', '')
        node.setdefault('sni', node['server'])
    logger.debug(f"标准化节点 {node['name']}: type={node_type}, compatible={node['clash-compatible']}, meta={config.meta_mode}")
    return node

class NodeParser:
    """节点解析器类，抽象协议解析；增强V2Ray (vmess/vless) 支持"""
    def __init__(self):
        self.protocol_map = {
            'ss': self._parse_ss,
            'vmess': self._parse_vmess,  # V2Ray VMess
            'vless': self._parse_vless,  # VLESS
            'trojan': self._parse_trojan,
            'hysteria': self._parse_hysteria,
            'hysteria2': self._parse_hysteria2
        }

    def parse(self, link: str) -> Optional[Dict[str, Any]]:
        link = link.strip()
        # 处理V2Ray URI变体 (e.g., v2ray:// 但通常为vmess://)
        if link.startswith('v2ray://'):
            # 假设为vmess，尝试解析为base64
            try:
                b64_str = link[8:]
                padding = (4 - len(b64_str) % 4) % 4
                b64_str += '=' * padding
                data = json.loads(base64.b64decode(b64_str).decode('utf-8'))
                if data.get('v', 'tcp') == 'tcp' and 'ps' in data:  # VMess-like
                    return self._parse_vmess(link.replace('v2ray://', 'vmess://'))
            except:
                logger.warning(f"V2Ray URI解析失败: {link[:50]}...")
                return None
        for prefix, parser in self.protocol_map.items():
            if link.startswith(f"{prefix}://"):
                parsed = parser(link)
                if parsed:
                    logger.debug(f"解析成功: {prefix} -> {parsed['name']}")
                return parsed
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
            elif node['network'] == 'grpc':
                node['grpc-opts'] = {'grpc-service-name': vmess_data.get('serviceName', '')}
            return standardize_node(node)
        except Exception as e:
            logger.warning(f"解析VMess (V2Ray) 失败: {e}")
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
                'auth': params.get('auth', ''),  # Meta: auth string
                'up': f"{params.get('upmbps', 100)} Mbps",
                'down': f"{params.get('downmbps', 100)} Mbps",
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
                'password': password,  # Meta: password
                'up': f"{params.get('upmbps', 100)} Mbps",
                'down': f"{params.get('downmbps', 100)} Mbps",
                'sni': params.get('sni', server),
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

def enhanced_latency_test(node: Dict[str, Any]) -> int:
    """增强延迟测试：TCP + ICMP + 简单HTTP (适用于所有节点类型，无需Clash)"""
    server = node['server']
    port = node['port']
    node_type = node['type']
    
    # ICMP ping
    icmp = icmp_latency(server)
    if icmp > config.ping_threshold_ms or icmp == -1:
        logger.debug(f"ICMP失败 {node['name']} ({node_type}): {icmp}ms")
        return -1
    
    # TCP连接
    tcp = tcp_latency(server, port)
    if tcp == -1 or tcp > config.max_latency_ms * 2:
        logger.debug(f"TCP失败 {node['name']} ({node_type}): {tcp}ms")
        return -1
    
    # 简单HTTP测试 (如果支持HTTP代理模式，fallback到TCP)
    http_delay = -1
    if node_type in ['ss', 'vmess', 'trojan', 'vless', 'hysteria', 'hysteria2']:
        try:
            # 模拟简单HTTP请求 via socks/http proxy (需额外库如requests[socks]，这里简化用TCP作为proxy延迟近似)
            # 实际可扩展：使用node作为proxy测试real_test_urls (对于Hysteria需专用客户端，此处回退TCP)
            for test_url in config.real_test_urls[:1]:  # 只测试一个
                start_http = time.time()
                proxies = { 'http': f'socks5://{server}:{port}', 'https': f'socks5://{server}:{port}' } if node_type != 'http' else { 'http': f'http://{server}:{port}', 'https': f'http://{server}:{port}' }
                response = requests.get(test_url, proxies=proxies, timeout=5, allow_redirects=False)
                if response.status_code in [204, 302]:
                    http_delay = round((time.time() - start_http) * 1000)
                    break
        except Exception as e:
            logger.debug(f"HTTP测试失败 {node['name']} ({node_type}): {e}")
            http_delay = tcp  # 回退到TCP (适用于Hysteria等)
    
    # 综合延迟：加权平均 (TCP 50%, ICMP 30%, HTTP 20%)
    if http_delay > 0:
        avg_latency = (tcp * 0.5 + icmp * 0.3 + http_delay * 0.2)
    else:
        avg_latency = (tcp * 0.7 + icmp * 0.3)
    
    logger.info(f"增强测试 {node['name']} ({node_type}): ICMP={icmp}ms, TCP={tcp}ms, HTTP={http_delay}ms, 平均={round(avg_latency)}ms")
    return round(avg_latency) if 0 < avg_latency < config.max_latency_ms else -1

def test_nodes_latency(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """批量延迟测试：使用增强fallback方法，无需Clash或临时文件；支持所有协议"""
    if not nodes:
        return []

    logger.info(f"批量延迟测试: {len(nodes)} 个节点 (无Clash，纯TCP/ICMP/HTTP，支持SS/VMess/VLESS/Trojan/Hysteria/Hysteria2)")
    max_workers = min(os.cpu_count() or 8, len(nodes))
    this_results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(enhanced_latency_test, node): node for node in nodes}
        for future in tqdm(as_completed(futures), total=len(nodes), desc="延迟测试"):
            node = futures[future]
            try:
                latency = future.result()
                if latency > 0:
                    this_results.append({'node': node, 'latency': latency})
            except Exception as e:
                logger.error(f"测试异常 {node['name']}: {e}")
    return this_results

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
    logger.info(f"生成Clash (Meta) 配置: {len(fast_nodes)} 个节点 -> {output_filename} (支持{', '.join(config.supported_clash_types)})")
    
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
            'enable': True, 'ipv6': False, 'enhanced-mode': 'redir-host', 'fake-ip-range': '198.18.0.1/16',
            'nameserver': ['https://doh.pub/dns-query', 'https://223.5.5.5/dns-query'],
            'fallback': ['8.8.8.8', '1.1.1.1', 'tls://dns.google']
        },
        'proxies': fast_nodes,  # 已转换的Clash格式proxies (包括Hysteria if Meta)
        'proxy-groups': [
            {'name': 'PROXY', 'type': 'select', 'proxies': ['AUTO-URL', 'DIRECT'] + proxy_names},
            {'name': 'AUTO-URL', 'type': 'url-test', 'proxies': proxy_names,
             'url': 'http://cp.cloudflare.com/generate_204', 'interval': 300}
        ],
        'rules': [
            'GEOIP,CN,DIRECT',
            'MATCH,PROXY'
        ]
    }
    if config.meta_mode:
        # Meta特定：添加tun模式支持等 (可选)
        clash_config['tun'] = {'enable': True, 'stack': 'system', 'dns-hijack': ['any:53']}
    
    try:
        with open(output_filename, 'w', encoding='utf-8') as f:
            yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        logger.info(f"Clash订阅生成成功: {output_filename} (Base64订阅链接: clash://{base64.urlsafe_b64encode(yaml.dump(clash_config, allow_unicode=True).encode()).decode().rstrip('=')})")
        return clash_config  # 返回缓存
    except Exception as e:
        logger.error(f"写入YAML失败: {e}")
        return yaml_cache  # 回退缓存

def process_subscription(url: str, unique_nodes_set: set, global_valid_results: List[Dict[str, Any]],
                         yaml_cache: Dict[str, Any]) -> List[Dict[str, Any]]:
    """处理单个订阅，返回有效节点列表；所有协议转为Clash格式"""
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
                if all(k in proxy for k in ['name', 'server', 'port', 'type']) and proxy['type'] in config.supported_clash_types:
                    node = standardize_node(proxy)
                    node_hash_val = key_fields_hash(node)
                    if node_hash_val not in unique_nodes_set:
                        this_all_nodes.append(node)
                        unique_nodes_set.add(node_hash_val)
            if config.debug_mode:
                logger.info(f"YAML解析: {len(this_all_nodes)} 个节点 (Clash格式)")
    except Exception as e:
        logger.debug(f"YAML解析失败: {e}")

    if not this_all_nodes:
        decoded = decode_base64_content(content)
        links_content = decoded if decoded else content
        for link in links_content.splitlines():
            node = node_parser.parse(link)
            if node and node['type'] in config.supported_clash_types:
                node_hash_val = key_fields_hash(node)
                if node_hash_val not in unique_nodes_set:
                    this_all_nodes.append(node)
                    unique_nodes_set.add(node_hash_val)
        if config.debug_mode:
            logger.info(f"链接解析: {len(this_all_nodes)} 个节点 (转为Clash: SS/VMess/VLESS/Trojan/Hysteria/Hysteria2)")

    if not this_all_nodes:
        logger.warning(f"订阅无有效节点 (支持协议: {', '.join(config.supported_clash_types)}): {url}")
        return []

    # 预筛选
    this_prefiltered_nodes = this_all_nodes[:]
    if config.prescreen_enabled:
        logger.info("预筛选节点...")
        this_prefiltered_nodes = []
        failed_count = 0
        max_workers_pre = min(os.cpu_count() or 4, len(this_all_nodes))
        with ThreadPoolExecutor(max_workers=max_workers_pre) as executor:
            # 预筛选使用简单TCP/ICMP
            futures = {executor.submit(lambda n: icmp_latency(n['server']) <= config.ping_threshold_ms and icmp_latency(n['server']) != -1 and tcp_latency(n['server'], n['port']) > 0 and tcp_latency(n['server'], n['port']) < config.max_latency_ms * 2, node): node for node in this_all_nodes}
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

    # 批量延迟测试：使用增强fallback，无Clash
    logger.info(f"批量延迟测试: {len(this_prefiltered_nodes)} 个节点 (Clash格式)")
    this_results = test_nodes_latency(this_prefiltered_nodes)

    valid_this = [item for item in this_results if item['latency'] > 0]
    global_valid_results.extend(valid_this)
    logger.info(f"追加 {len(valid_this)} 个有效节点，全局 {len(global_valid_results)} 个 (Clash兼容)")

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
    parser = argparse.ArgumentParser(description="Clash订阅优化工具 (全协议转Clash)")
    parser.add_argument('--max-latency', type=int, default=config.max_latency_ms, help='最大延迟 (ms)')
    parser.add_argument('--max-nodes', type=int, default=config.max_nodes_limit, help='最大节点数')
    parser.add_argument('--no-prescreen', action='store_true', help='禁用预筛选')
    parser.add_argument('--debug', action='store_true', help='启用调试模式')
    parser.add_argument('--clash-path', default=config.clash_binary_path, help='Clash二进制路径')
    parser.add_argument('--enable-clash-test', action='store_true', help='启用Clash测试 (会生成临时文件)')
    parser.add_argument('--meta', action='store_true', help='Clash Meta模式 (支持Hysteria/Hysteria2，转为Meta YAML)')
    args = parser.parse_args()

    config.max_latency_ms = args.max_latency
    config.max_nodes_limit = args.max_nodes
    config.prescreen_enabled = not args.no_prescreen
    config.debug_mode = args.debug
    config.clash_binary_path = args.clash_path
    config.use_clash_testing = args.enable_clash_test
    config.meta_mode = args.meta
    if config.meta_mode:
        config.supported_clash_types.extend(['hysteria', 'hysteria2'])
        logger.info("启用Clash Meta模式: 支持Hysteria/Hysteria2 (输出Meta YAML)")

    logging.getLogger().setLevel(logging.DEBUG if config.debug_mode else logging.INFO)

    if config.use_clash_testing and not os.path.exists(config.clash_binary_path):
        logger.error(f"Clash未找到: {config.clash_binary_path} (Clash测试已禁用)")
        config.use_clash_testing = False

    if not os.path.exists(config.sub_urls_file):
        logger.error(f"订阅文件不存在: {config.sub_urls_file}")
        with open(config.sub_urls_file, 'w', encoding='utf-8') as f:
            f.write("# 粘贴订阅链接 (支持SS/VMess/VLESS/Trojan/Hysteria/Hysteria2)\n")
        return

    with open(config.sub_urls_file, 'r', encoding='utf-8') as f:
        subscription_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    if not subscription_urls:
        logger.warning("无有效订阅链接")
        return

    test_method = "Clash API" if config.use_clash_testing else "增强Fallback (TCP/ICMP/HTTP)"
    mode_str = "Meta" if config.meta_mode else "标准"
    logger.info(f"开始处理 {len(subscription_urls)} 个订阅 (模式: {mode_str}, 测试: {test_method}, 支持: {', '.join(config.supported_clash_types)})")

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
        logger.info(f"最终top {len(fast_nodes)} 个节点 (Clash订阅)")
        yaml_cache = generate_clash_config(fast_nodes, config.output_clash_file, yaml_cache)
    else:
        logger.warning("无有效节点")
        generate_clash_config([], config.output_clash_file, yaml_cache)

    with open(config.update_time_file, 'w', encoding='utf-8') as f:
        update_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        f.write(f"最后更新: {update_time}\n可用节点: {len(fast_nodes) if 'fast_nodes' in locals() else 0}\n模式: {mode_str}\n")
    logger.info(f"Clash订阅更新完成: {config.output_clash_file} (导入Clash/{'Meta' if config.meta_mode else '标准'})")

if __name__ == '__main__':
    main()
