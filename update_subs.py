#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Clash/V2Ray 订阅聚合 & 节点测试工具
支持协议: VMess, VLESS, Trojan, SS, SSR, Hysteria2, TUIC, AnyTLS
输出: Clash YAML + V2Ray Base64 订阅文件
"""

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
from urllib.parse import unquote, urlparse, parse_qs, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import hashlib
import urllib3

urllib3.disable_warnings()

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# ==================== 全局配置 ====================
SUBSCRIPTION_URLS_FILE = 'sub_urls.txt'
OUTPUT_CLASH_FILE = 'sub.yaml'
OUTPUT_CLASH_FILE_SCHOLAR = 'sub_scholar.yaml'
OUTPUT_V2RAY_BASE64_FILE = 'sub_v2ray_base64.txt'  # V2Ray base64订阅文件
UPDATE_TIME_FILE = 'update_time.txt'

# 两阶段测试配置
STAGE1_V2RAY_TEST = True
STAGE1_TOP_N = 2000
STAGE2_SCHOLAR_TEST = True

# V2ray测试配置
V2RAY_BINARY_PATH = './v2ray'
V2RAY_TEST_TIMEOUT = 3.0
V2RAY_TEST_URL = 'https://www.gstatic.com/generate_204'

# Clash测试配置
CLASH_BINARY_PATH = './clash'
MAX_LATENCY_MS = 500
MAX_NODES_LIMIT = 500

# 并发控制
MAX_WORKERS_FETCH = 20
MAX_WORKERS_V2RAY = 50
MAX_WORKERS_CLASH = 8

# 学术/Scholar验证配置
SCHOLAR_VERIFY_URL = 'https://scholar.google.com/scholar?q=test'

# HTTP Session (复用连接提升效率)
_session = None

def get_session():
    global _session
    if _session is None:
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=50,
            pool_maxsize=100,
            max_retries=1
        )
        _session = requests.Session()
        _session.mount('http://', adapter)
        _session.mount('https://', adapter)
    return _session

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('test.log', encoding='utf-8', mode='w')
    ]
)
logger = logging.getLogger(__name__)

# ==================== 工具函数 ====================
def random_string(length=6):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]

def node_hash(node):
    key = f"{node.get('type')}:{node.get('server')}:{node.get('port')}"
    return hashlib.md5(key.encode()).hexdigest()

def standardize_node(node):
    defaults = {'udp': True, 'skip-cert-verify': False}
    for key, value in defaults.items():
        node.setdefault(key, value)
    if 'port' in node:
        node['port'] = int(node['port'])
    node = {k: v for k, v in node.items() if v is not None and v != ''}
    return node

# ==================== 节点解析 ====================
def get_subscription_content(url):
    headers = {'User-Agent': 'ClashforWindows/0.20.39 clash-verge/1.7.7'}
    try:
        logger.info(f"获取订阅: {url[:80]}...")
        resp = get_session().get(url, timeout=20, headers=headers, verify=False)
        resp.raise_for_status()
        resp.encoding = 'utf-8'
        return resp.text
    except Exception as e:
        logger.error(f"获取失败 [{url[:50]}]: {e}")
        return None

def decode_base64_content(content):
    try:
        content = content.strip()
        padding = (4 - len(content) % 4) % 4
        content += '=' * padding
        return base64.b64decode(content.encode('ascii')).decode('utf-8')
    except:
        return None

def parse_node(link):
    link = link.strip()
    if not link:
        return None
    if link.startswith('vmess://'):      return parse_vmess_link(link)
    elif link.startswith('vless://'):    return parse_vless_link(link)
    elif link.startswith('trojan://'):   return parse_trojan_link(link)
    elif link.startswith('ss://'):       return parse_ss_link(link)
    elif link.startswith('ssr://'):      return parse_ssr_link(link)
    elif link.startswith('hysteria2://'): return parse_hysteria2_link(link)
    elif link.startswith('hy2://'):      return parse_hysteria2_link(link)
    elif link.startswith('tuic://'):     return parse_tuic_link(link)
    elif link.startswith('anytls://'):   return parse_anytls_link(link)
    return None

def parse_vmess_link(link):
    try:
        b64 = link[8:]
        padding = (4 - len(b64) % 4) % 4
        data = json.loads(base64.b64decode(b64 + '=' * padding).decode('utf-8'))
        if not all(k in data for k in ['add', 'port', 'id']):
            return None
        node = {
            'name': (data.get('ps') or f"vmess_{data['add']}").strip(),
            'type': 'vmess',
            'server': data['add'],
            'port': int(data['port']),
            'uuid': data['id'],
            'alterId': int(data.get('aid', 0)),
            'cipher': data.get('scy', 'auto') or 'auto',
            'tls': data.get('tls', '') == 'tls',
            'network': data.get('net', 'tcp') or 'tcp'
        }
        net = node['network']
        if net == 'ws':
            ws = {'path': data.get('path', '/')}
            if data.get('host'):
                ws['headers'] = {'Host': data['host']}
            node['ws-opts'] = ws
        elif net == 'h2':
            h2 = {'path': data.get('path', '/')}
            if data.get('host'):
                h2['host'] = [data['host']]
            node['h2-opts'] = h2
        elif net == 'grpc':
            if data.get('path'):
                node['grpc-opts'] = {'grpc-service-name': data['path']}
        elif net == 'httpupgrade':
            hu = {'path': data.get('path', '/')}
            if data.get('host'):
                hu['host'] = data['host']
            node['httpupgrade-opts'] = hu
        if node['tls'] and data.get('sni'):
            node['servername'] = data['sni']
        if data.get('fp'):
            node['client-fingerprint'] = data['fp']
        return standardize_node(node)
    except Exception as e:
        logger.debug(f"VMess解析失败: {e}")
        return None

def parse_vless_link(link):
    try:
        parts = urlparse(link)
        if '@' not in parts.netloc:
            return None
        uuid, host_info = parts.netloc.split('@', 1)
        server, port = host_info.rsplit(':', 1)
        params = {k: v[0] if v else '' for k, v in parse_qs(parts.query).items()}
        security = params.get('security', '')
        node = {
            'name': unquote(parts.fragment).strip() if parts.fragment else f"vless_{server}",
            'type': 'vless',
            'server': server,
            'port': int(port),
            'uuid': uuid,
            'network': params.get('type', 'tcp'),
            'tls': security in ['tls', 'reality']
        }
        if security == 'reality':
            node['reality-opts'] = {}
            if params.get('pbk'):
                node['reality-opts']['public-key'] = params['pbk']
            if params.get('sid'):
                node['reality-opts']['short-id'] = params['sid']
        if node['tls']:
            if params.get('sni'):
                node['servername'] = params['sni']
            if params.get('fp'):
                node['client-fingerprint'] = params['fp']
        net = node['network']
        if net == 'ws':
            ws = {}
            if params.get('path'):
                ws['path'] = unquote(params['path'])
            if params.get('host'):
                ws['headers'] = {'Host': params['host']}
            if ws:
                node['ws-opts'] = ws
        elif net == 'grpc':
            if params.get('serviceName'):
                node['grpc-opts'] = {'grpc-service-name': params['serviceName']}
        elif net == 'h2':
            h2 = {}
            if params.get('path'):
                h2['path'] = unquote(params['path'])
            if params.get('host'):
                h2['host'] = [params['host']]
            if h2:
                node['h2-opts'] = h2
        elif net == 'httpupgrade':
            hu = {}
            if params.get('path'):
                hu['path'] = unquote(params['path'])
            if params.get('host'):
                hu['host'] = params['host']
            if hu:
                node['httpupgrade-opts'] = hu
        if params.get('flow'):
            node['flow'] = params['flow']
        return standardize_node(node)
    except Exception as e:
        logger.debug(f"VLESS解析失败: {e}")
        return None

def parse_trojan_link(link):
    try:
        parts = urlparse(link)
        if '@' not in parts.netloc:
            return None
        password, host_info = parts.netloc.split('@', 1)
        server, port = host_info.rsplit(':', 1)
        params = {k: v[0] if v else '' for k, v in parse_qs(parts.query).items()}
        node = {
            'name': unquote(parts.fragment).strip() if parts.fragment else f"trojan_{server}",
            'type': 'trojan',
            'server': server,
            'port': int(port),
            'password': unquote(password),
            'sni': params.get('sni', server)
        }
        net = params.get('type', '')
        if net == 'ws':
            node['network'] = 'ws'
            ws = {}
            if params.get('path'):
                ws['path'] = unquote(params['path'])
            if params.get('host'):
                ws['headers'] = {'Host': params['host']}
            if ws:
                node['ws-opts'] = ws
        elif net == 'grpc':
            node['network'] = 'grpc'
            if params.get('serviceName'):
                node['grpc-opts'] = {'grpc-service-name': params['serviceName']}
        if params.get('alpn'):
            node['alpn'] = params['alpn'].split(',')
        if params.get('allowInsecure') in ['1', 'true']:
            node['skip-cert-verify'] = True
        if params.get('fp'):
            node['client-fingerprint'] = params['fp']
        return standardize_node(node)
    except Exception as e:
        logger.debug(f"Trojan解析失败: {e}")
        return None

def parse_ss_link(link):
    try:
        parts = urlparse(link)
        if '@' in parts.netloc:
            user_info, host_info = parts.netloc.split('@', 1)
            server, port = host_info.rsplit(':', 1)
            try:
                user_info_str = base64.urlsafe_b64decode(user_info + '===').decode('utf-8')
            except:
                user_info_str = unquote(user_info)
            if ':' not in user_info_str:
                return None
            method, password = user_info_str.split(':', 1)
        else:
            try:
                decoded = base64.urlsafe_b64decode(parts.netloc + '===').decode('utf-8')
            except:
                return None
            if '@' not in decoded:
                return None
            user_info, host_info = decoded.split('@', 1)
            server, port = host_info.rsplit(':', 1)
            method, password = user_info.split(':', 1)
        node = {
            'name': unquote(parts.fragment).strip() if parts.fragment else f"ss_{server}",
            'type': 'ss',
            'server': server,
            'port': int(port),
            'cipher': method,
            'password': password
        }
        params = {k: v[0] if v else '' for k, v in parse_qs(parts.query).items()}
        if params.get('plugin'):
            plugin_info = params['plugin'].split(';')
            if 'obfs' in plugin_info[0]:
                node['plugin'] = 'obfs'
                node['plugin-opts'] = {}
                for opt in plugin_info[1:]:
                    if '=' in opt:
                        k, v = opt.split('=', 1)
                        if k == 'obfs':
                            node['plugin-opts']['mode'] = v
                        elif k == 'obfs-host':
                            node['plugin-opts']['host'] = v
            elif 'v2ray-plugin' in plugin_info[0]:
                node['plugin'] = 'v2ray-plugin'
                opts = {}
                for opt in plugin_info[1:]:
                    if '=' in opt:
                        k, v = opt.split('=', 1)
                        opts[k] = v
                node['plugin-opts'] = opts
        return standardize_node(node)
    except Exception as e:
        logger.debug(f"SS解析失败: {e}")
        return None

def parse_ssr_link(link):
    try:
        raw = link[6:]
        padding = (4 - len(raw) % 4) % 4
        decoded = base64.urlsafe_b64decode(raw + '=' * padding).decode('utf-8')
        parts = decoded.split('/')
        main = parts[0].split(':')
        if len(main) < 6:
            return None
        server, port, protocol, method, obfs, password_b64 = main[:6]
        password = base64.urlsafe_b64decode(password_b64.split('?')[0] + '===').decode('utf-8')
        if method in ['aes-256-cfb', 'aes-128-cfb', 'chacha20', 'chacha20-ietf', 'aes-256-gcm', 'aes-128-gcm', 'chacha20-ietf-poly1305']:
            return standardize_node({
                'name': f"ssr_{server}",
                'type': 'ss',
                'server': server,
                'port': int(port),
                'cipher': method,
                'password': password
            })
        return None
    except Exception as e:
        logger.debug(f"SSR解析失败: {e}")
        return None

def parse_hysteria2_link(link):
    try:
        if link.startswith('hysteria2://'):
            link = link[12:]
        elif link.startswith('hy2://'):
            link = link[6:]
        parts = urlparse(f"hysteria2://{link}")
        if '@' not in parts.netloc:
            return None
        password, host_info = parts.netloc.split('@', 1)
        # 处理IPv6
        if host_info.startswith('['):
            bracket_end = host_info.index(']')
            server = host_info[:bracket_end + 1]
            port = host_info[bracket_end + 2:]
        else:
            server, port = host_info.rsplit(':', 1)
        params = {k: v[0] if v else '' for k, v in parse_qs(parts.query).items()}
        node = {
            'name': unquote(parts.fragment).strip() if parts.fragment else f"hy2_{server}",
            'type': 'hysteria2',
            'server': server.strip('[]'),
            'port': int(port),
            'password': unquote(password)
        }
        if params.get('sni'):
            node['sni'] = params['sni']
        if params.get('alpn'):
            node['alpn'] = params['alpn'].split(',')
        if params.get('insecure') in ['1', 'true']:
            node['skip-cert-verify'] = True
        if params.get('up'):
            node['up'] = params['up']
        if params.get('down'):
            node['down'] = params['down']
        if params.get('obfs'):
            node['obfs'] = params['obfs']
            if params.get('obfs-password'):
                node['obfs-password'] = params['obfs-password']
        return standardize_node(node)
    except Exception as e:
        logger.debug(f"Hysteria2解析失败: {e}")
        return None

def parse_tuic_link(link):
    """解析TUIC v5链接: tuic://uuid:password@host:port?params#name"""
    try:
        parts = urlparse(link)
        if '@' not in parts.netloc:
            return None
        user_info, host_info = parts.netloc.split('@', 1)
        if ':' in user_info:
            uuid, password = user_info.split(':', 1)
        else:
            uuid = user_info
            password = ''
        if ':' not in host_info:
            return None
        server, port = host_info.rsplit(':', 1)
        params = {k: v[0] if v else '' for k, v in parse_qs(parts.query).items()}
        node = {
            'name': unquote(parts.fragment).strip() if parts.fragment else f"tuic_{server}",
            'type': 'tuic',
            'server': server,
            'port': int(port),
            'uuid': unquote(uuid),
            'password': unquote(password),
            'congestion-controller': params.get('congestion_control', 'bbr'),
            'udp-relay-mode': params.get('udp_relay_mode', 'native'),
            'reduce-rtt': True
        }
        if params.get('sni'):
            node['sni'] = params['sni']
        if params.get('alpn'):
            node['alpn'] = params['alpn'].split(',')
        if params.get('disable_sni') in ['1', 'true']:
            node['disable-sni'] = True
        if params.get('allow_insecure') in ['1', 'true'] or params.get('insecure') in ['1', 'true']:
            node['skip-cert-verify'] = True
        return standardize_node(node)
    except Exception as e:
        logger.debug(f"TUIC解析失败: {e}")
        return None

def parse_anytls_link(link):
    """解析AnyTLS链接: anytls://password@host:port?params#name"""
    try:
        parts = urlparse(link)
        if '@' not in parts.netloc:
            return None
        password, host_info = parts.netloc.split('@', 1)
        if ':' not in host_info:
            return None
        server, port = host_info.rsplit(':', 1)
        params = {k: v[0] if v else '' for k, v in parse_qs(parts.query).items()}
        node = {
            'name': unquote(parts.fragment).strip() if parts.fragment else f"anytls_{server}",
            'type': 'anytls',
            'server': server,
            'port': int(port),
            'password': unquote(password)
        }
        if params.get('sni'):
            node['sni'] = params['sni']
        if params.get('alpn'):
            node['alpn'] = params['alpn'].split(',')
        if params.get('insecure') in ['1', 'true']:
            node['skip-cert-verify'] = True
        if params.get('fp'):
            node['client-fingerprint'] = params['fp']
        if params.get('idle-session-check-interval'):
            node['idle-session-check-interval'] = int(params['idle-session-check-interval'])
        if params.get('min-idle-session'):
            node['min-idle-session'] = int(params['min-idle-session'])
        return standardize_node(node)
    except Exception as e:
        logger.debug(f"AnyTLS解析失败: {e}")
        return None

# ==================== 节点反序列化为URI ====================
def node_to_uri(node):
    """将节点dict转换回URI字符串，用于生成V2Ray base64订阅"""
    t = node.get('type', '')
    try:
        if t == 'vmess':    return node_to_vmess_uri(node)
        if t == 'vless':    return node_to_vless_uri(node)
        if t == 'trojan':   return node_to_trojan_uri(node)
        if t == 'ss':       return node_to_ss_uri(node)
        if t == 'hysteria2': return node_to_hysteria2_uri(node)
        if t == 'tuic':     return node_to_tuic_uri(node)
        if t == 'anytls':   return node_to_anytls_uri(node)
    except Exception as e:
        logger.debug(f"节点转URI失败 [{node.get('name')}]: {e}")
    return None

def node_to_vmess_uri(node):
    data = {
        'v': '2',
        'ps': node.get('name', ''),
        'add': node.get('server', ''),
        'port': str(node.get('port', '')),
        'id': node.get('uuid', ''),
        'aid': str(node.get('alterId', 0)),
        'scy': node.get('cipher', 'auto'),
        'net': node.get('network', 'tcp'),
        'tls': 'tls' if node.get('tls') else '',
        'sni': node.get('servername', ''),
        'fp': node.get('client-fingerprint', '')
    }
    ws_opts = node.get('ws-opts', {})
    if ws_opts:
        data['path'] = ws_opts.get('path', '/')
        headers = ws_opts.get('headers', {})
        data['host'] = headers.get('Host', '')
    h2_opts = node.get('h2-opts', {})
    if h2_opts:
        data['path'] = h2_opts.get('path', '/')
        hosts = h2_opts.get('host', [])
        data['host'] = hosts[0] if hosts else ''
    grpc_opts = node.get('grpc-opts', {})
    if grpc_opts:
        data['path'] = grpc_opts.get('grpc-service-name', '')
    encoded = base64.b64encode(json.dumps(data, ensure_ascii=False).encode()).decode()
    return f"vmess://{encoded}"

def node_to_vless_uri(node):
    params = {}
    params['type'] = node.get('network', 'tcp')
    if node.get('tls'):
        if node.get('reality-opts'):
            params['security'] = 'reality'
            ro = node['reality-opts']
            if ro.get('public-key'):
                params['pbk'] = ro['public-key']
            if ro.get('short-id'):
                params['sid'] = ro['short-id']
        else:
            params['security'] = 'tls'
    if node.get('servername'):
        params['sni'] = node['servername']
    if node.get('client-fingerprint'):
        params['fp'] = node['client-fingerprint']
    if node.get('flow'):
        params['flow'] = node['flow']
    ws_opts = node.get('ws-opts', {})
    if ws_opts:
        params['path'] = ws_opts.get('path', '/')
        headers = ws_opts.get('headers', {})
        if headers.get('Host'):
            params['host'] = headers['Host']
    grpc_opts = node.get('grpc-opts', {})
    if grpc_opts:
        params['serviceName'] = grpc_opts.get('grpc-service-name', '')
    query = '&'.join(f"{k}={quote(str(v))}" for k, v in params.items() if v)
    name = quote(node.get('name', ''))
    return f"vless://{node['uuid']}@{node['server']}:{node['port']}?{query}#{name}"

def node_to_trojan_uri(node):
    params = {}
    if node.get('sni'):
        params['sni'] = node['sni']
    net = node.get('network', '')
    if net:
        params['type'] = net
    ws_opts = node.get('ws-opts', {})
    if ws_opts:
        params['path'] = ws_opts.get('path', '/')
        headers = ws_opts.get('headers', {})
        if headers.get('Host'):
            params['host'] = headers['Host']
    alpn = node.get('alpn', [])
    if alpn:
        params['alpn'] = ','.join(alpn)
    if node.get('skip-cert-verify'):
        params['allowInsecure'] = '1'
    query = '&'.join(f"{k}={quote(str(v))}" for k, v in params.items() if v)
    name = quote(node.get('name', ''))
    pw = quote(node.get('password', ''))
    return f"trojan://{pw}@{node['server']}:{node['port']}?{query}#{name}"

def node_to_ss_uri(node):
    method = node.get('cipher', '')
    password = node.get('password', '')
    user_info = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip('=')
    name = quote(node.get('name', ''))
    return f"ss://{user_info}@{node['server']}:{node['port']}#{name}"

def node_to_hysteria2_uri(node):
    params = {}
    if node.get('sni'):
        params['sni'] = node['sni']
    alpn = node.get('alpn', [])
    if alpn:
        params['alpn'] = ','.join(alpn)
    if node.get('skip-cert-verify'):
        params['insecure'] = '1'
    if node.get('up'):
        params['up'] = node['up']
    if node.get('down'):
        params['down'] = node['down']
    if node.get('obfs'):
        params['obfs'] = node['obfs']
    if node.get('obfs-password'):
        params['obfs-password'] = node['obfs-password']
    query = '&'.join(f"{k}={quote(str(v))}" for k, v in params.items() if v)
    name = quote(node.get('name', ''))
    pw = quote(node.get('password', ''))
    q_str = f"?{query}" if query else ''
    return f"hysteria2://{pw}@{node['server']}:{node['port']}{q_str}#{name}"

def node_to_tuic_uri(node):
    params = {}
    if node.get('sni'):
        params['sni'] = node['sni']
    alpn = node.get('alpn', [])
    if alpn:
        params['alpn'] = ','.join(alpn)
    if node.get('congestion-controller'):
        params['congestion_control'] = node['congestion-controller']
    if node.get('udp-relay-mode'):
        params['udp_relay_mode'] = node['udp-relay-mode']
    if node.get('skip-cert-verify'):
        params['allow_insecure'] = '1'
    query = '&'.join(f"{k}={quote(str(v))}" for k, v in params.items() if v)
    name = quote(node.get('name', ''))
    uuid = quote(node.get('uuid', ''))
    pw = quote(node.get('password', ''))
    q_str = f"?{query}" if query else ''
    return f"tuic://{uuid}:{pw}@{node['server']}:{node['port']}{q_str}#{name}"

def node_to_anytls_uri(node):
    params = {}
    if node.get('sni'):
        params['sni'] = node['sni']
    alpn = node.get('alpn', [])
    if alpn:
        params['alpn'] = ','.join(alpn)
    if node.get('skip-cert-verify'):
        params['insecure'] = '1'
    if node.get('client-fingerprint'):
        params['fp'] = node['client-fingerprint']
    query = '&'.join(f"{k}={quote(str(v))}" for k, v in params.items() if v)
    name = quote(node.get('name', ''))
    pw = quote(node.get('password', ''))
    q_str = f"?{query}" if query else ''
    return f"anytls://{pw}@{node['server']}:{node['port']}{q_str}#{name}"

# ==================== V2Ray Base64订阅生成 ====================
def generate_v2ray_base64_subscription(nodes, output_file):
    """生成V2Ray兼容的base64订阅文件"""
    logger.info(f"生成V2Ray Base64订阅: {len(nodes)} 个节点 -> {output_file}")
    uris = []
    for node in nodes:
        uri = node_to_uri(node)
        if uri:
            uris.append(uri)
    content = '\n'.join(uris)
    encoded = base64.b64encode(content.encode('utf-8')).decode('utf-8')
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(encoded)
    logger.info(f"✓ V2Ray Base64订阅已生成: {output_file} ({len(uris)} 个节点)")
    # 同时保存明文版
    plain_file = output_file.replace('.txt', '_plain.txt')
    with open(plain_file, 'w', encoding='utf-8') as f:
        f.write(content)
    logger.info(f"✓ 节点明文文件已生成: {plain_file}")

# ==================== 节点解析总入口 ====================
def parse_all_nodes(all_contents):
    all_nodes = []
    unique_set = set()

    for url, content in all_contents.items():
        nodes = []
        # 尝试YAML解析 (Clash格式)
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict) and 'proxies' in data:
                for proxy in data['proxies']:
                    if all(k in proxy for k in ['name', 'server', 'port', 'type']):
                        node = standardize_node(dict(proxy))
                        h = node_hash(node)
                        if h not in unique_set:
                            nodes.append(node)
                            unique_set.add(h)
        except:
            pass

        # 尝试链接行解析
        if not nodes:
            decoded = decode_base64_content(content) or content
            for line in decoded.splitlines():
                line = line.strip()
                node = parse_node(line)
                if node:
                    h = node_hash(node)
                    if h not in unique_set:
                        nodes.append(node)
                        unique_set.add(h)

        all_nodes.extend(nodes)
        if nodes:
            logger.info(f"  └─ 解析: {len(nodes)} 个节点 ({url[:60]})")

    logger.info(f"总解析: {len(all_nodes)} 个唯一节点")
    return all_nodes

# ==================== 节点格式验证 ====================
def validate_clash_node(node):
    required = ['name', 'type', 'server', 'port']
    if not all(f in node for f in required):
        return False
    t = node['type']
    if t == 'vmess':
        return 'uuid' in node and 'alterId' in node
    elif t == 'vless':
        return 'uuid' in node
    elif t == 'trojan':
        return 'password' in node
    elif t == 'ss':
        return 'password' in node and 'cipher' in node
    elif t == 'hysteria2':
        return 'password' in node
    elif t == 'tuic':
        return 'uuid' in node and 'password' in node
    elif t == 'anytls':
        return 'password' in node
    return True

# ==================== 阶段1: V2ray快速延迟测试 ====================
def generate_v2ray_config(node, socks_port, http_port):
    config = {
        "log": {"loglevel": "none"},
        "inbounds": [
            {"port": socks_port, "listen": "127.0.0.1", "protocol": "socks",
             "settings": {"udp": True, "auth": "noauth"}},
            {"port": http_port, "listen": "127.0.0.1", "protocol": "http"}
        ],
        "outbounds": [{"protocol": "freedom"}]
    }
    t = node['type']
    if t == 'vmess':
        outbound = {
            "protocol": "vmess",
            "settings": {"vnext": [{"address": node['server'], "port": node['port'],
                "users": [{"id": node['uuid'], "alterId": node.get('alterId', 0),
                           "security": node.get('cipher', 'auto')}]}]},
            "streamSettings": {"network": node.get('network', 'tcp')}
        }
        if node.get('tls'):
            outbound['streamSettings']['security'] = 'tls'
            tls_s = {'allowInsecure': node.get('skip-cert-verify', False)}
            if node.get('servername'):
                tls_s['serverName'] = node['servername']
            outbound['streamSettings']['tlsSettings'] = tls_s
        if node.get('network') == 'ws' and node.get('ws-opts'):
            wo = node['ws-opts']
            outbound['streamSettings']['wsSettings'] = {
                'path': wo.get('path', '/'), 'headers': wo.get('headers', {})}
        config['outbounds'] = [outbound]

    elif t == 'vless':
        outbound = {
            "protocol": "vless",
            "settings": {"vnext": [{"address": node['server'], "port": node['port'],
                "users": [{"id": node['uuid'], "encryption": "none",
                           "flow": node.get('flow', '')}]}]},
            "streamSettings": {"network": node.get('network', 'tcp')}
        }
        if node.get('tls'):
            outbound['streamSettings']['security'] = 'tls'
            tls_s = {'allowInsecure': node.get('skip-cert-verify', False)}
            if node.get('servername'):
                tls_s['serverName'] = node['servername']
            outbound['streamSettings']['tlsSettings'] = tls_s
        if node.get('network') == 'ws' and node.get('ws-opts'):
            wo = node['ws-opts']
            outbound['streamSettings']['wsSettings'] = {
                'path': wo.get('path', '/'), 'headers': wo.get('headers', {})}
        config['outbounds'] = [outbound]

    elif t == 'trojan':
        outbound = {
            "protocol": "trojan",
            "settings": {"servers": [{"address": node['server'], "port": node['port'],
                "password": node['password']}]},
            "streamSettings": {
                "security": "tls",
                "tlsSettings": {
                    "serverName": node.get('sni', node['server']),
                    "allowInsecure": node.get('skip-cert-verify', False)
                }
            }
        }
        config['outbounds'] = [outbound]

    elif t == 'ss':
        outbound = {
            "protocol": "shadowsocks",
            "settings": {"servers": [{"address": node['server'], "port": node['port'],
                "method": node['cipher'], "password": node['password']}]}
        }
        config['outbounds'] = [outbound]

    # Hysteria2 / TUIC / AnyTLS 通过Clash测试，V2ray不直接支持
    return config

def test_node_with_v2ray(node):
    # 这些协议跳过V2ray测试，直接进入Clash阶段
    if node['type'] in ('hysteria2', 'tuic', 'anytls'):
        return 0  # 返回0表示"跳过，直接通过"

    rand_id = random_string()
    config_path = f'/tmp/v2ray_{rand_id}.json'
    socks_port = get_free_port()
    http_port = get_free_port()
    process = None
    try:
        config = generate_v2ray_config(node, socks_port, http_port)
        with open(config_path, 'w') as f:
            json.dump(config, f)

        process = subprocess.Popen(
            [V2RAY_BINARY_PATH, 'run', '-c', config_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1.2)

        proxies = {
            'http': f'http://127.0.0.1:{http_port}',
            'https': f'http://127.0.0.1:{http_port}'
        }
        start = time.time()
        try:
            r = get_session().get(V2RAY_TEST_URL, proxies=proxies,
                                   timeout=V2RAY_TEST_TIMEOUT, verify=False)
            if r.status_code in [200, 204]:
                delay = round((time.time() - start) * 1000)
                logger.info(f"✓ V2ray {node['name']}: {delay}ms")
                return delay
        except:
            pass
        return -1
    except Exception as e:
        logger.debug(f"V2ray测试失败 {node.get('name')}: {e}")
        return -1
    finally:
        if process:
            try:
                process.terminate()
                process.wait(timeout=2)
            except:
                try: process.kill()
                except: pass
        try: os.remove(config_path)
        except: pass

def stage1_v2ray_test(nodes):
    logger.info(f"\n{'='*60}")
    logger.info(f"[阶段1/2] V2ray快速延迟测试 ({len(nodes)} 个节点)")
    logger.info(f"{'='*60}")

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_V2RAY) as executor:
        futures = {executor.submit(test_node_with_v2ray, node): node for node in nodes}
        for future in tqdm(as_completed(futures), total=len(nodes), desc="V2ray测试"):
            node = futures[future]
            try:
                delay = future.result(timeout=V2RAY_TEST_TIMEOUT + 8)
                if delay >= 0:  # 0=跳过协议直通, >0=实测延迟
                    results.append({'node': node, 'delay': delay if delay > 0 else 9999})
            except:
                pass

    results.sort(key=lambda x: x['delay'])
    top = results[:STAGE1_TOP_N]
    logger.info(f"✓ 阶段1完成: {len(top)}/{len(nodes)} 个节点通过")
    return [item['node'] for item in top]

# ==================== 阶段2: Clash Scholar验证 ====================
def wait_for_clash_api(api_addr, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(f'http://{api_addr}/version', timeout=1)
            if r.status_code == 200:
                return True
        except:
            pass
        time.sleep(0.3)
    return False

def verify_scholar_access(socks_address, node_name):
    if not STAGE2_SCHOLAR_TEST:
        return True
    try:
        proxies = {
            'http': f'socks5h://{socks_address}',
            'https': f'socks5h://{socks_address}'
        }
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
            'Accept-Language': 'en-US,en;q=0.9'
        }
        r = requests.get(SCHOLAR_VERIFY_URL, proxies=proxies, timeout=15,
                         headers=headers, verify=False)
        if r.status_code == 200:
            cl = r.text.lower()
            blocked = any(kw in cl for kw in ['captcha', 'automated queries', '/sorry/index', 'unusual traffic'])
            if not blocked:
                logger.info(f"✓ Scholar可访问: {node_name}")
                return True
            else:
                logger.warning(f"✗ Scholar受限: {node_name}")
        else:
            logger.debug(f"✗ Scholar状态码{r.status_code}: {node_name}")
    except Exception as e:
        logger.debug(f"Scholar连接异常 [{node_name}]: {e}")
    return False

def test_node_with_clash_scholar(node):
    rand_id = random_string()
    config_path = f'/tmp/clash_{rand_id}.yaml'
    api_port = get_free_port()
    socks_port = get_free_port()
    process = None

    cfg = {
        'proxies': [node],
        'external-controller': f'127.0.0.1:{api_port}',
        'socks-port': socks_port,
        'log-level': 'silent',
        'allow-lan': False
    }
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(cfg, f, allow_unicode=True, sort_keys=False)

        process = subprocess.Popen(
            [CLASH_BINARY_PATH, '-f', config_path, '-d', '/tmp'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        if not wait_for_clash_api(f'127.0.0.1:{api_port}', timeout=10):
            logger.debug(f"Clash启动超时: {node['name']}")
            return None

        if verify_scholar_access(f'127.0.0.1:{socks_port}', node['name']):
            return node
        return None
    except Exception as e:
        logger.debug(f"Clash测试失败 {node['name']}: {e}")
        return None
    finally:
        if process:
            try: process.terminate(); process.wait(timeout=2)
            except:
                try: process.kill()
                except: pass
        try: os.remove(config_path)
        except: pass
        time.sleep(0.2)

def stage2_clash_scholar_test(nodes):
    logger.info(f"\n{'='*60}")
    logger.info(f"[阶段2/2] Clash + Google Scholar验证 ({len(nodes)} 个节点)")
    logger.info(f"{'='*60}")

    valid = [n for n in nodes if validate_clash_node(n)]
    logger.info(f"格式验证: {len(valid)}/{len(nodes)} 个节点有效")
    if not valid:
        return []

    passed = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_CLASH) as executor:
        futures = {executor.submit(test_node_with_clash_scholar, n): n for n in valid}
        for future in tqdm(as_completed(futures), total=len(valid), desc="Scholar验证"):
            try:
                result = future.result(timeout=35)
                if result:
                    passed.append(result)
                    if len(passed) >= MAX_NODES_LIMIT:
                        for f in futures:
                            f.cancel()
                        break
            except:
                pass
            time.sleep(random.uniform(0.3, 0.6))

    logger.info(f"✓ 阶段2完成: {len(passed)} 个节点通过Scholar验证")
    return passed

# ==================== Clash配置生成 ====================
def ensure_unique_names(nodes):
    name_count = {}
    result = []
    for node in nodes:
        name = node['name']
        if name in name_count:
            name_count[name] += 1
            node = dict(node)
            node['name'] = f"{name}_{name_count[name]}"
        else:
            name_count[name] = 1
        result.append(node)
    return result

def generate_clash_config(nodes, output_file, title="Aggregated"):
    logger.info(f"生成Clash配置: {len(nodes)} 个节点 -> {output_file}")
    config = {
        'port': 7890,
        'socks-port': 7891,
        'mixed-port': 7892,
        'allow-lan': False,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'dns': {
            'enabled': True,
            'enhanced-mode': 'fake-ip',
            'fake-ip-range': '198.18.0.1/16',
            'nameserver': ['https://doh.pub/dns-query', '223.5.5.5'],
            'fallback': ['8.8.8.8', '1.1.1.1', 'https://dns.google/dns-query'],
            'fallback-filter': {'geoip': True, 'geoip-code': 'CN'}
        },
        'proxies': nodes
    }
    if nodes:
        names = [n['name'] for n in nodes]
        config['proxy-groups'] = [
            {'name': 'PROXY', 'type': 'select', 'proxies': ['AUTO', 'FALLBACK', 'DIRECT'] + names},
            {'name': 'AUTO', 'type': 'url-test', 'proxies': names,
             'url': 'http://www.gstatic.com/generate_204', 'interval': 300, 'tolerance': 50},
            {'name': 'FALLBACK', 'type': 'fallback', 'proxies': names,
             'url': 'http://www.gstatic.com/generate_204', 'interval': 300}
        ]
    else:
        config['proxy-groups'] = [{'name': 'PROXY', 'type': 'select', 'proxies': ['DIRECT']}]

    config['rules'] = [
        'DOMAIN-SUFFIX,scholar.google.com,PROXY',
        'DOMAIN-SUFFIX,google.com,PROXY',
        'DOMAIN-SUFFIX,googleapis.com,PROXY',
        'DOMAIN-SUFFIX,github.com,PROXY',
        'DOMAIN-SUFFIX,openai.com,PROXY',
        'DOMAIN-SUFFIX,gemini.google.com,PROXY',
        'GEOIP,CN,DIRECT',
        'MATCH,PROXY'
    ]
    with open(output_file, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)
    logger.info(f"✓ Clash配置已生成: {output_file}")

# ==================== 主流程 ====================
def main():
    logger.info("="*60)
    logger.info("节点聚合测试工具 v2.0 - 支持VMess/VLESS/Trojan/SS/Hy2/TUIC/AnyTLS")
    logger.info("="*60)

    # 检查核心
    if STAGE1_V2RAY_TEST and not os.path.exists(V2RAY_BINARY_PATH):
        logger.warning(f"V2ray未找到({V2RAY_BINARY_PATH})，将跳过阶段1测试")
        globals()['STAGE1_V2RAY_TEST'] = False

    if not os.path.exists(CLASH_BINARY_PATH):
        logger.error(f"Clash核心未找到: {CLASH_BINARY_PATH}")
        logger.info("下载: https://github.com/MetaCubeX/mihomo/releases")
        sys.exit(1)

    # 读取订阅
    if not os.path.exists(SUBSCRIPTION_URLS_FILE):
        with open(SUBSCRIPTION_URLS_FILE, 'w', encoding='utf-8') as f:
            f.write("# 每行一个订阅URL\n# https://example.com/sub\n")
        logger.error(f"请在 {SUBSCRIPTION_URLS_FILE} 中添加订阅链接")
        return

    with open(SUBSCRIPTION_URLS_FILE, 'r', encoding='utf-8') as f:
        urls = [l.strip() for l in f if l.strip() and not l.startswith('#')]

    if not urls:
        logger.warning("无有效订阅链接")
        return

    logger.info(f"订阅数: {len(urls)}")

    # 并发获取订阅
    logger.info("\n获取订阅内容...")
    contents = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_FETCH) as executor:
        futures = {executor.submit(get_subscription_content, url): url for url in urls}
        for future in tqdm(as_completed(futures), total=len(futures), desc="获取订阅"):
            url = futures[future]
            content = future.result()
            if content:
                contents[url] = content

    logger.info(f"成功: {len(contents)}/{len(urls)} 个订阅")
    if not contents:
        logger.error("所有订阅获取失败")
        return

    # 解析节点
    all_nodes = parse_all_nodes(contents)
    if not all_nodes:
        logger.warning("未解析到任何节点")
        return

    # 阶段1: V2ray测试
    if STAGE1_V2RAY_TEST:
        stage1_nodes = stage1_v2ray_test(all_nodes)
    else:
        stage1_nodes = all_nodes[:STAGE1_TOP_N]
        logger.info(f"跳过V2ray测试，直接使用前{len(stage1_nodes)}个节点")

    stage1_nodes = ensure_unique_names(stage1_nodes)

    # 生成第一阶段输出
    generate_clash_config(stage1_nodes, OUTPUT_CLASH_FILE)
    generate_v2ray_base64_subscription(stage1_nodes, OUTPUT_V2RAY_BASE64_FILE)

    with open(UPDATE_TIME_FILE, 'w', encoding='utf-8') as f:
        f.write(f"更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"总节点数: {len(all_nodes)}\n")
        f.write(f"阶段1节点: {len(stage1_nodes)}\n")
        f.write(f"订阅来源: {len(contents)}\n")

    if not stage1_nodes:
        logger.warning("阶段1无可用节点")
        return

    # 阶段2: Clash Scholar验证
    final_nodes = stage2_clash_scholar_test(stage1_nodes)

    if final_nodes:
        final_nodes = ensure_unique_names(final_nodes)
        generate_clash_config(final_nodes, OUTPUT_CLASH_FILE_SCHOLAR)
        scholar_v2ray = OUTPUT_V2RAY_BASE64_FILE.replace('.txt', '_scholar.txt')
        generate_v2ray_base64_subscription(final_nodes, scholar_v2ray)

        with open(UPDATE_TIME_FILE, 'a', encoding='utf-8') as f:
            f.write(f"Scholar节点: {len(final_nodes)}\n")

        logger.info(f"\n{'='*60}")
        logger.info(f"✓ 完成！{len(final_nodes)} 个Scholar可用节点")
        logger.info(f"  Clash配置: {OUTPUT_CLASH_FILE_SCHOLAR}")
        logger.info(f"  V2Ray订阅: {scholar_v2ray}")
        logger.info(f"{'='*60}")
    else:
        logger.warning("阶段2无Scholar可用节点")
        generate_clash_config([], OUTPUT_CLASH_FILE_SCHOLAR)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\n用户中断")
        sys.exit(0)
    except Exception as e:
        logger.error(f"运行错误: {e}", exc_info=True)
        sys.exit(1)
