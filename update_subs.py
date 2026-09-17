#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Clash/V2Ray 订阅聚合 & 节点深度过滤工具 v2.3
支持协议: VMess, VLESS (含 Reality), Trojan, SS, SSR, Hysteria2, TUIC, AnyTLS
核心优化:
  1. 前置深度清洗: 自动剥离广告、收敛数万个重复的 CDN 优选 IP 与多端口轰炸
  2. 严格防假活: 禁用重定向 (allow_redirects=False)，严格比对 204 状态码
  3. 环境隔离: 屏蔽系统全局代理 (trust_env=False)，杜绝本地测试穿透
  4. 协议分流: 现代协议自动由 Mihomo (Clash Meta) 接管测试
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
import hashlib
import ipaddress
from datetime import datetime
from urllib.parse import unquote, urlparse, parse_qs, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import urllib3

urllib3.disable_warnings()

# ==================== 全局配置 ====================
SUBSCRIPTION_URLS_FILE    = 'sub_urls.txt'
OUTPUT_CLASH_FILE         = 'sub.yaml'
OUTPUT_CLASH_FILE_SCHOLAR = 'sub_scholar.yaml'
OUTPUT_V2RAY_BASE64_FILE  = 'sub_v2ray_base64.txt'
UPDATE_TIME_FILE          = 'update_time.txt'

# 节点清洗与去重参数
MAX_PRE_TEST_NODES        = 3000   # 前置清洗后，允许进入测速的最大节点上限 (防 Actions 超时)
MAX_PER_CDN_BACKEND       = 2      # 同一个 CDN 后端 (相同 UUID+SNI/Host) 最多保留的优选 IP 数
MAX_PER_SERVER_IP         = 2      # 同一个服务器 IP 最多保留的不同端口节点数

# 测速阶段开关
STAGE1_V2RAY_TEST         = True   # 阶段1: 延迟初筛
STAGE1_TOP_N              = 1500   # 阶段1保留前N个节点
STAGE15_REAL_TEST         = True   # 阶段1.5: 真连接 Google 测试 (两轮)
STAGE2_SCHOLAR_TEST       = True   # 阶段2: Google Scholar 学术免验证码测试

# 核心可执行文件路径 (Actions 脚本会自动准备)
V2RAY_BINARY_PATH         = './v2ray'
CLASH_BINARY_PATH         = './clash'

V2RAY_TEST_TIMEOUT        = 3.5    # 延迟测试超时(秒)
REAL_TEST_TIMEOUT         = 6.0    # 真实连接超时(秒)
REAL_TEST_URL             = 'https://www.google.com/generate_204'

# 并发控制
MAX_WORKERS_FETCH         = 20
MAX_WORKERS_V2RAY         = 30
MAX_WORKERS_REAL          = 20
MAX_WORKERS_CLASH         = 6
MAX_NODES_LIMIT           = 500

# 学术测试目标
SCHOLAR_VERIFY_URL        = 'https://scholar.google.com/scholar?q=test'

# 广告与提示类节点关键词过滤列表
AD_KEYWORDS = [
    '剩余', '到期', '过期', '官网', '通知', '群', 'tg', 'channel', 'http',
    '更新', '重置', '套餐', '维护', '公告', '返利', '购买', '注册', '广告',
    '网址', '客服', '备用', '说明', '规则', '流量', '时间', '订阅', '防失联'
]

# 日志输出配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('test.log', encoding='utf-8', mode='w')
    ]
)
logger = logging.getLogger(__name__)

# ==================== 安全请求封装 ====================
def safe_request_get(url, proxies=None, timeout=5, allow_redirects=False, headers=None):
    """
    隔离请求：
    1. 强制 trust_env=False 杜绝环境代理或系统全局代理污染测速
    2. 默认禁止重定向，杜绝 ISP 或拦截页的假 200 返回
    """
    with requests.Session() as s:
        s.trust_env = False
        return s.get(url, proxies=proxies, timeout=timeout, verify=False,
                     allow_redirects=allow_redirects, headers=headers)

# ==================== 基础工具函数 ====================
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
    for k, v in {'udp': True, 'skip-cert-verify': False}.items():
        node.setdefault(k, v)
    if 'port' in node:
        try:
            node['port'] = int(node['port'])
        except:
            return None
    return {k: v for k, v in node.items() if v is not None and v != ''}

def is_modern_protocol(node):
    """判断是否需要交由 Clash Meta/Mihomo 测试的高阶协议"""
    if node.get('type') in ('hysteria2', 'tuic', 'anytls'):
        return True
    if node.get('type') == 'vless' and node.get('reality-opts'):
        return True
    return False

# ==================== 节点深度清洗与去重 ====================
def is_junk_node(node):
    name = node.get('name', '').lower()
    server = str(node.get('server', '')).strip().lower()
    port = node.get('port', 0)

    if not (1 <= port <= 65535):
        return True

    for kw in AD_KEYWORDS:
        if kw in name:
            return True

    if server in ['127.0.0.1', 'localhost', '0.0.0.0', '1.1.1.1']:
        return True

    try:
        ip = ipaddress.ip_address(server)
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
            return True
    except ValueError:
        if '.' not in server or len(server) < 4:
            return True

    return False

def clean_and_deduplicate_nodes(nodes, max_limit=MAX_PRE_TEST_NODES):
    logger.info(f"\n{'='*60}")
    logger.info(f"[前置过滤] 开始深度清洗去重 (原始抓取节点总数: {len(nodes)})")
    logger.info(f"{'='*60}")

    # 1. 过滤垃圾与广告节点
    valid_nodes = [n for n in nodes if not is_junk_node(n)]
    logger.info(f"1. 广告与垃圾过滤: 剔除 {len(nodes) - len(valid_nodes)} 个，保留有效节点 {len(valid_nodes)}")

    # 2. 严格特征去重 (type + server + port)
    unique_exact = []
    exact_set = set()
    for n in valid_nodes:
        key = f"{n.get('type')}:{str(n.get('server')).lower()}:{n.get('port')}"
        if key not in exact_set:
            exact_set.add(key)
            unique_exact.append(n)
    logger.info(f"2. IP+端口去重: 剔除重复 {len(valid_nodes) - len(unique_exact)} 个，剩余 {len(unique_exact)}")

    # 3. CDN 优选 IP 轰炸收敛 (核心：聚合压缩同质化 Worker 节点)
    cdn_clusters = {}
    non_cdn_nodes = []
    for n in unique_exact:
        sni = n.get('servername') or n.get('sni') or ''
        host = n.get('ws-opts', {}).get('headers', {}).get('Host', '')
        path = n.get('ws-opts', {}).get('path', '')
        uuid = n.get('uuid') or n.get('password') or ''

        if sni or host:
            cluster_key = f"{n.get('type')}:{uuid}:{sni}:{host}:{path}"
            cdn_clusters.setdefault(cluster_key, []).append(n)
        else:
            non_cdn_nodes.append(n)

    cdn_retained = []
    cdn_pruned_count = 0
    for _, cluster_nodes in cdn_clusters.items():
        if len(cluster_nodes) > MAX_PER_CDN_BACKEND:
            cdn_pruned_count += (len(cluster_nodes) - MAX_PER_CDN_BACKEND)
            cdn_retained.extend(cluster_nodes[:MAX_PER_CDN_BACKEND])
        else:
            cdn_retained.extend(cluster_nodes)

    logger.info(f"3. CDN 优选 IP 收敛: 压缩同质化节点 {cdn_pruned_count} 个，保留代表 {len(cdn_retained)}")

    combined_nodes = non_cdn_nodes + cdn_retained

    # 4. 单服务器 IP 多端口收敛
    server_ip_counts = {}
    final_nodes = []
    for n in combined_nodes:
        srv = str(n.get('server')).lower()
        cnt = server_ip_counts.get(srv, 0)
        if cnt < MAX_PER_SERVER_IP:
            server_ip_counts[srv] = cnt + 1
            final_nodes.append(n)
    logger.info(f"4. 单 IP 端口轰炸收敛: 剩余 {len(final_nodes)} 个节点")

    # 5. 上限安全截断
    if len(final_nodes) > max_limit:
        random.seed(42)
        random.shuffle(final_nodes)
        logger.warning(f"⚠️ 节点数仍有 {len(final_nodes)} 个，截取前 {max_limit} 个送入测试阶段")
        final_nodes = final_nodes[:max_limit]

    logger.info(f"✓ 预处理完成！最终送测候选节点数: {len(final_nodes)}\n")
    return final_nodes

# ==================== 节点协议解析 ====================
def get_subscription_content(url):
    headers = {'User-Agent': 'ClashforWindows/0.20.39 clash-verge/1.7.7'}
    try:
        r = requests.get(url, timeout=15, headers=headers, verify=False)
        r.raise_for_status()
        r.encoding = 'utf-8'
        return r.text
    except Exception as e:
        logger.error(f"获取订阅失败 [{url[:40]}]: {e}")
        return None

def decode_base64_content(content):
    try:
        content = content.strip()
        padding = (4 - len(content) % 4) % 4
        return base64.b64decode((content + '=' * padding).encode('ascii')).decode('utf-8')
    except:
        return None

def parse_node(link):
    link = link.strip()
    if not link: return None
    if link.startswith('vmess://'):       return parse_vmess_link(link)
    if link.startswith('vless://'):       return parse_vless_link(link)
    if link.startswith('trojan://'):      return parse_trojan_link(link)
    if link.startswith('ss://'):          return parse_ss_link(link)
    if link.startswith('ssr://'):         return parse_ssr_link(link)
    if link.startswith('hysteria2://') or link.startswith('hy2://'):
        return parse_hysteria2_link(link)
    if link.startswith('tuic://'):        return parse_tuic_link(link)
    if link.startswith('anytls://'):      return parse_anytls_link(link)
    return None

def parse_vmess_link(link):
    try:
        b64 = link[8:]
        data = json.loads(base64.b64decode(b64 + '=' * ((4 - len(b64) % 4) % 4)).decode())
        if not all(k in data for k in ['add', 'port', 'id']): return None
        node = {
            'name': (data.get('ps') or f"vmess_{data['add']}").strip(),
            'type': 'vmess', 'server': data['add'], 'port': int(data['port']),
            'uuid': data['id'], 'alterId': int(data.get('aid', 0)),
            'cipher': data.get('scy', 'auto') or 'auto',
            'tls': data.get('tls', '') == 'tls',
            'network': data.get('net', 'tcp') or 'tcp'
        }
        net = node['network']
        if net == 'ws':
            ws = {'path': data.get('path', '/')}
            if data.get('host'): ws['headers'] = {'Host': data['host']}
            node['ws-opts'] = ws
        elif net == 'h2':
            h2 = {'path': data.get('path', '/')}
            if data.get('host'): h2['host'] = [data['host']]
            node['h2-opts'] = h2
        elif net == 'grpc':
            if data.get('path'): node['grpc-opts'] = {'grpc-service-name': data['path']}
        elif net == 'httpupgrade':
            hu = {'path': data.get('path', '/')}
            if data.get('host'): hu['host'] = data['host']
            node['httpupgrade-opts'] = hu
        if node['tls'] and data.get('sni'): node['servername'] = data['sni']
        if data.get('fp'): node['client-fingerprint'] = data['fp']
        return standardize_node(node)
    except: return None

def parse_vless_link(link):
    try:
        parts = urlparse(link)
        if '@' not in parts.netloc: return None
        uuid, host_info = parts.netloc.split('@', 1)
        server, port = host_info.rsplit(':', 1)
        params = {k: v[0] for k, v in parse_qs(parts.query).items() if v}
        security = params.get('security', '')
        node = {
            'name': unquote(parts.fragment).strip() if parts.fragment else f"vless_{server}",
            'type': 'vless', 'server': server, 'port': int(port), 'uuid': uuid,
            'network': params.get('type', 'tcp'), 'tls': security in ['tls', 'reality']
        }
        if security == 'reality':
            ro = {}
            if params.get('pbk'): ro['public-key'] = params['pbk']
            if params.get('sid'): ro['short-id'] = params['sid']
            node['reality-opts'] = ro
        if node['tls']:
            if params.get('sni'): node['servername'] = params['sni']
            if params.get('fp'): node['client-fingerprint'] = params['fp']
        net = node['network']
        if net == 'ws':
            ws = {}
            if params.get('path'): ws['path'] = unquote(params['path'])
            if params.get('host'): ws['headers'] = {'Host': params['host']}
            if ws: node['ws-opts'] = ws
        elif net == 'grpc':
            if params.get('serviceName'):
                node['grpc-opts'] = {'grpc-service-name': params['serviceName']}
        if params.get('flow'): node['flow'] = params['flow']
        return standardize_node(node)
    except: return None

def parse_trojan_link(link):
    try:
        parts = urlparse(link)
        if '@' not in parts.netloc: return None
        password, host_info = parts.netloc.split('@', 1)
        server, port = host_info.rsplit(':', 1)
        params = {k: v[0] for k, v in parse_qs(parts.query).items() if v}
        node = {
            'name': unquote(parts.fragment).strip() if parts.fragment else f"trojan_{server}",
            'type': 'trojan', 'server': server, 'port': int(port),
            'password': unquote(password), 'sni': params.get('sni', server)
        }
        net = params.get('type', '')
        if net == 'ws':
            node['network'] = 'ws'
            ws = {}
            if params.get('path'): ws['path'] = unquote(params['path'])
            if params.get('host'): ws['headers'] = {'Host': params['host']}
            if ws: node['ws-opts'] = ws
        elif net == 'grpc':
            node['network'] = 'grpc'
            if params.get('serviceName'):
                node['grpc-opts'] = {'grpc-service-name': params['serviceName']}
        if params.get('alpn'): node['alpn'] = params['alpn'].split(',')
        if params.get('allowInsecure') in ['1', 'true']: node['skip-cert-verify'] = True
        return standardize_node(node)
    except: return None

def parse_ss_link(link):
    try:
        parts = urlparse(link)
        if '@' in parts.netloc:
            user_info, host_info = parts.netloc.split('@', 1)
            server, port = host_info.rsplit(':', 1)
            try: user_info_str = base64.urlsafe_b64decode(user_info + '===').decode()
            except: user_info_str = unquote(user_info)
            if ':' not in user_info_str: return None
            method, password = user_info_str.split(':', 1)
        else:
            try: decoded = base64.urlsafe_b64decode(parts.netloc + '===').decode()
            except: return None
            if '@' not in decoded: return None
            user_info, host_info = decoded.split('@', 1)
            server, port = host_info.rsplit(':', 1)
            method, password = user_info.split(':', 1)
        node = {
            'name': unquote(parts.fragment).strip() if parts.fragment else f"ss_{server}",
            'type': 'ss', 'server': server, 'port': int(port),
            'cipher': method, 'password': password
        }
        return standardize_node(node)
    except: return None

def parse_ssr_link(link):
    try:
        raw = link[6:]
        decoded = base64.urlsafe_b64decode(raw + '=' * ((4 - len(raw) % 4) % 4)).decode()
        main = decoded.split('/')[0].split(':')
        if len(main) < 6: return None
        server, port, _, method, _, password_b64 = main[:6]
        password = base64.urlsafe_b64decode(password_b64.split('?')[0] + '===').decode()
        if method in ['aes-256-cfb', 'aes-128-cfb', 'chacha20', 'chacha20-ietf',
                      'aes-256-gcm', 'aes-128-gcm', 'chacha20-ietf-poly1305']:
            return standardize_node({'name': f"ssr_{server}", 'type': 'ss',
                'server': server, 'port': int(port), 'cipher': method, 'password': password})
        return None
    except: return None

def parse_hysteria2_link(link):
    try:
        raw = link[12:] if link.startswith('hysteria2://') else link[6:]
        parts = urlparse(f"hysteria2://{raw}")
        if '@' not in parts.netloc: return None
        password, host_info = parts.netloc.split('@', 1)
        if host_info.startswith('['):
            i = host_info.index(']')
            server, port = host_info[:i+1].strip('[]'), host_info[i+2:]
        else:
            server, port = host_info.rsplit(':', 1)
        params = {k: v[0] for k, v in parse_qs(parts.query).items() if v}
        node = {
            'name': unquote(parts.fragment).strip() if parts.fragment else f"hy2_{server}",
            'type': 'hysteria2', 'server': server, 'port': int(port),
            'password': unquote(password)
        }
        if params.get('sni'): node['sni'] = params['sni']
        if params.get('alpn'): node['alpn'] = params['alpn'].split(',')
        if params.get('insecure') in ['1', 'true']: node['skip-cert-verify'] = True
        return standardize_node(node)
    except: return None

def parse_tuic_link(link):
    try:
        parts = urlparse(link)
        if '@' not in parts.netloc: return None
        user_info, host_info = parts.netloc.split('@', 1)
        uuid, password = user_info.split(':', 1) if ':' in user_info else (user_info, '')
        server, port = host_info.rsplit(':', 1)
        params = {k: v[0] for k, v in parse_qs(parts.query).items() if v}
        node = {
            'name': unquote(parts.fragment).strip() if parts.fragment else f"tuic_{server}",
            'type': 'tuic', 'server': server, 'port': int(port),
            'uuid': unquote(uuid), 'password': unquote(password),
            'congestion-controller': params.get('congestion_control', 'bbr'),
            'udp-relay-mode': params.get('udp_relay_mode', 'native'),
            'reduce-rtt': True
        }
        if params.get('sni'): node['sni'] = params['sni']
        if params.get('alpn'): node['alpn'] = params['alpn'].split(',')
        return standardize_node(node)
    except: return None

def parse_anytls_link(link):
    try:
        parts = urlparse(link)
        if '@' not in parts.netloc: return None
        password, host_info = parts.netloc.split('@', 1)
        server, port = host_info.rsplit(':', 1)
        params = {k: v[0] for k, v in parse_qs(parts.query).items() if v}
        node = {
            'name': unquote(parts.fragment).strip() if parts.fragment else f"anytls_{server}",
            'type': 'anytls', 'server': server, 'port': int(port),
            'password': unquote(password)
        }
        if params.get('sni'): node['sni'] = params['sni']
        return standardize_node(node)
    except: return None

# ==================== 节点转 URI 格式 ====================
def node_to_uri(node):
    t = node.get('type', '')
    try:
        if t == 'vmess':     return _vmess_uri(node)
        if t == 'vless':     return _vless_uri(node)
        if t == 'trojan':    return _trojan_uri(node)
        if t == 'ss':        return _ss_uri(node)
        if t == 'hysteria2': return _hysteria2_uri(node)
        if t == 'tuic':      return _tuic_uri(node)
    except: pass
    return None

def _vmess_uri(n):
    data = {'v': '2', 'ps': n.get('name',''), 'add': n.get('server',''),
            'port': str(n.get('port','')), 'id': n.get('uuid',''),
            'aid': str(n.get('alterId',0)), 'scy': n.get('cipher','auto'),
            'net': n.get('network','tcp'), 'tls': 'tls' if n.get('tls') else '',
            'sni': n.get('servername','')}
    return f"vmess://{base64.b64encode(json.dumps(data).encode()).decode()}"

def _vless_uri(n):
    p = {'type': n.get('network','tcp')}
    if n.get('tls'):
        p['security'] = 'reality' if n.get('reality-opts') else 'tls'
        if n.get('reality-opts'):
            ro = n['reality-opts']
            if ro.get('public-key'): p['pbk'] = ro['public-key']
            if ro.get('short-id'): p['sid'] = ro['short-id']
    if n.get('servername'): p['sni'] = n['servername']
    if n.get('flow'): p['flow'] = n['flow']
    q = '&'.join(f"{k}={quote(str(v))}" for k,v in p.items() if v)
    return f"vless://{n['uuid']}@{n['server']}:{n['port']}?{q}#{quote(n.get('name',''))}"

def _trojan_uri(n):
    return f"trojan://{quote(n['password'])}@{n['server']}:{n['port']}?sni={n.get('sni', n['server'])}#{quote(n.get('name',''))}"

def _ss_uri(n):
    ui = base64.urlsafe_b64encode(f"{n['cipher']}:{n['password']}".encode()).decode().rstrip('=')
    return f"ss://{ui}@{n['server']}:{n['port']}#{quote(n.get('name',''))}"

def _hysteria2_uri(n):
    return f"hysteria2://{quote(n['password'])}@{n['server']}:{n['port']}?sni={n.get('sni','')}#{quote(n.get('name',''))}"

def _tuic_uri(n):
    return f"tuic://{quote(n['uuid'])}:{quote(n['password'])}@{n['server']}:{n['port']}#{quote(n.get('name',''))}"

# ==================== 解析主入口 ====================
def parse_all_nodes(all_contents):
    all_nodes, unique_set = [], set()
    for url, content in all_contents.items():
        nodes = []
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict) and 'proxies' in data:
                for proxy in data['proxies']:
                    if all(k in proxy for k in ['name','server','port','type']):
                        node = standardize_node(dict(proxy))
                        if node:
                            h = node_hash(node)
                            if h not in unique_set:
                                nodes.append(node); unique_set.add(h)
        except: pass
        if not nodes:
            decoded = decode_base64_content(content) or content
            for line in decoded.splitlines():
                node = parse_node(line.strip())
                if node:
                    h = node_hash(node)
                    if h not in unique_set:
                        nodes.append(node); unique_set.add(h)
        all_nodes.extend(nodes)
        if nodes: logger.info(f"  └─ {len(nodes)} 个节点 ({url[:50]}...)")
    logger.info(f"订阅抓取合并完成: 共提取到 {len(all_nodes)} 个节点")
    return all_nodes

# ==================== 核心进程管理 ====================
def _start_v2ray(node, socks_port, http_port):
    config = {
        "log": {"loglevel": "none"},
        "inbounds": [
            {"port": socks_port, "listen": "127.0.0.1", "protocol": "socks",
             "settings": {"udp": True, "auth": "noauth"}},
            {"port": http_port, "listen": "127.0.0.1", "protocol": "http"}
        ],
        "outbounds": []
    }
    t = node['type']
    if t == 'vmess':
        ob = {
            "protocol": "vmess",
            "settings": {"vnext": [{"address": node['server'], "port": node['port'],
                "users": [{"id": node['uuid'], "alterId": node.get('alterId',0),
                           "security": node.get('cipher','auto')}]}]},
            "streamSettings": {"network": node.get('network','tcp')}
        }
        if node.get('tls'):
            ob['streamSettings']['security'] = 'tls'
            ob['streamSettings']['tlsSettings'] = {
                'serverName': node.get('servername',''),
                'allowInsecure': node.get('skip-cert-verify', False)
            }
        config['outbounds'] = [ob]

    elif t == 'vless':
        ob = {
            "protocol": "vless",
            "settings": {"vnext": [{"address": node['server'], "port": node['port'],
                "users": [{"id": node['uuid'], "encryption": "none", "flow": node.get('flow','')}]}]},
            "streamSettings": {"network": node.get('network','tcp')}
        }
        if node.get('tls'):
            ob['streamSettings']['security'] = 'tls'
            ob['streamSettings']['tlsSettings'] = {
                'serverName': node.get('servername',''),
                'allowInsecure': node.get('skip-cert-verify', False)
            }
        config['outbounds'] = [ob]

    elif t == 'trojan':
        config['outbounds'] = [{"protocol": "trojan",
            "settings": {"servers": [{"address": node['server'], "port": node['port'],
                "password": node['password']}]},
            "streamSettings": {"security": "tls",
                "tlsSettings": {"serverName": node.get('sni', node['server']),
                                "allowInsecure": node.get('skip-cert-verify', False)}}}]

    elif t == 'ss':
        config['outbounds'] = [{"protocol": "shadowsocks",
            "settings": {"servers": [{"address": node['server'], "port": node['port'],
                "method": node['cipher'], "password": node['password']}]}}]

    rand_id = random_string()
    config_path = f'/tmp/v2ray_{rand_id}.json'
    with open(config_path, 'w') as f:
        json.dump(config, f)
    process = subprocess.Popen(
        [V2RAY_BINARY_PATH, 'run', '-c', config_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    return process, config_path

def _kill_process(process):
    if process:
        try: process.terminate(); process.wait(timeout=1.5)
        except:
            try: process.kill()
            except: pass

def _wait_for_clash_api(api_addr, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = safe_request_get(f'http://{api_addr}/version', timeout=1)
            if r.status_code == 200: return True
        except: pass
        time.sleep(0.2)
    return False

# ==================== 阶段 1: 延迟初筛 ====================
def test_node_with_v2ray(node):
    if is_modern_protocol(node):
        return 0  # 现代协议直通，由支持它的 Mihomo 测速

    socks_port, http_port = get_free_port(), get_free_port()
    process, config_path = None, None
    try:
        process, config_path = _start_v2ray(node, socks_port, http_port)
        time.sleep(0.8)
        proxies = {'http': f'http://127.0.0.1:{http_port}', 'https': f'http://127.0.0.1:{http_port}'}
        start = time.time()
        # 严禁跟随重定向，严格要求 204
        r = safe_request_get('https://www.gstatic.com/generate_204',
                             proxies=proxies, timeout=V2RAY_TEST_TIMEOUT, allow_redirects=False)
        if r.status_code == 204:
            return round((time.time() - start) * 1000)
    except: pass
    finally:
        _kill_process(process)
        try: os.remove(config_path)
        except: pass
    return -1

def stage1_v2ray_test(nodes):
    logger.info(f"\n{'='*60}")
    logger.info(f"[阶段1/3] 延迟初筛 ({len(nodes)} 个候选节点)")
    logger.info(f"{'='*60}")
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_V2RAY) as ex:
        futures = {ex.submit(test_node_with_v2ray, n): n for n in nodes}
        for future in tqdm(as_completed(futures), total=len(nodes), desc="延迟初筛"):
            node = futures[future]
            try:
                delay = future.result(timeout=V2RAY_TEST_TIMEOUT + 5)
                if delay >= 0:
                    results.append({'node': node, 'delay': delay if delay > 0 else 9999})
            except: pass
    results.sort(key=lambda x: x['delay'])
    top = results[:STAGE1_TOP_N]
    logger.info(f"✓ 阶段1完成: {len(top)}/{len(nodes)} 节点通过初筛")
    return [x['node'] for x in top]

# ==================== 阶段 1.5: 真实连接校验 ====================
def _test_real_google_v2ray(node):
    socks_port, http_port = get_free_port(), get_free_port()
    process, config_path = None, None
    try:
        process, config_path = _start_v2ray(node, socks_port, http_port)
        time.sleep(1.0)
        proxies = {'http': f'http://127.0.0.1:{http_port}', 'https': f'http://127.0.0.1:{http_port}'}
        start = time.time()
        r = safe_request_get(REAL_TEST_URL, proxies=proxies, timeout=REAL_TEST_TIMEOUT,
                             allow_redirects=False, headers={'User-Agent': 'Mozilla/5.0'})
        if r.status_code == 204:
            return round((time.time() - start) * 1000)
    except: pass
    finally:
        _kill_process(process)
        try: os.remove(config_path)
        except: pass
    return -1

def _test_real_google_clash(node):
    rand_id = random_string()
    config_path = f'/tmp/clash_real_{rand_id}.yaml'
    api_port, socks_port = get_free_port(), get_free_port()
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
        if not _wait_for_clash_api(f'127.0.0.1:{api_port}', timeout=8):
            return -1
        proxies = {'http': f'socks5h://127.0.0.1:{socks_port}',
                   'https': f'socks5h://127.0.0.1:{socks_port}'}
        start = time.time()
        r = safe_request_get(REAL_TEST_URL, proxies=proxies, timeout=REAL_TEST_TIMEOUT,
                             allow_redirects=False, headers={'User-Agent': 'Mozilla/5.0'})
        if r.status_code == 204:
            return round((time.time() - start) * 1000)
    except: pass
    finally:
        _kill_process(process)
        try: os.remove(config_path)
        except: pass
    return -1

def test_real_google(node):
    if is_modern_protocol(node):
        return _test_real_google_clash(node)
    return _test_real_google_v2ray(node)

def stage_real_google_test(nodes, pass_num=1):
    label = f"阶段1.{pass_num*2+3}/3" if pass_num == 2 else "阶段1.5/3"
    logger.info(f"\n{'='*60}")
    logger.info(f"[{label}] 真连接 Google 严苛测试 第{pass_num}轮 ({len(nodes)} 个节点)")
    logger.info(f"  目标: {REAL_TEST_URL} (严禁跳转重定向)")
    logger.info(f"{'='*60}")

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_REAL) as ex:
        futures = {ex.submit(test_real_google, n): n for n in nodes}
        for future in tqdm(as_completed(futures), total=len(nodes), desc=f"真连接测试[第{pass_num}轮]"):
            node = futures[future]
            try:
                delay = future.result(timeout=REAL_TEST_TIMEOUT + 8)
                if delay > 0:
                    results.append({'node': node, 'delay': delay})
            except: pass

    results.sort(key=lambda x: x['delay'])
    passed = [x['node'] for x in results]
    logger.info(f"✓ 第{pass_num}轮完成: {len(passed)}/{len(nodes)} 个节点真实可用")
    return passed

# ==================== 阶段 2: Scholar 学术验证 ====================
def verify_scholar_access(socks_address, node_name):
    if not STAGE2_SCHOLAR_TEST: return True
    try:
        proxies = {'http': f'socks5h://{socks_address}', 'https': f'socks5h://{socks_address}'}
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
                   'Accept-Language': 'en-US,en;q=0.9'}
        r = safe_request_get(SCHOLAR_VERIFY_URL, proxies=proxies, timeout=12,
                             allow_redirects=True, headers=headers)
        if r.status_code == 200:
            cl = r.text.lower()
            blocked = any(kw in cl for kw in ['captcha','automated queries','/sorry/index','unusual traffic'])
            if not blocked:
                logger.info(f"✓ Scholar免验证通过: {node_name}")
                return True
    except: pass
    return False

def test_node_with_clash_scholar(node):
    rand_id = random_string()
    config_path = f'/tmp/clash_{rand_id}.yaml'
    api_port, socks_port = get_free_port(), get_free_port()
    process = None
    cfg = {'proxies': [node], 'external-controller': f'127.0.0.1:{api_port}',
           'socks-port': socks_port, 'log-level': 'silent', 'allow-lan': False}
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(cfg, f, allow_unicode=True, sort_keys=False)
        process = subprocess.Popen(
            [CLASH_BINARY_PATH, '-f', config_path, '-d', '/tmp'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        if not _wait_for_clash_api(f'127.0.0.1:{api_port}', timeout=8):
            return None
        return node if verify_scholar_access(f'127.0.0.1:{socks_port}', node['name']) else None
    except: return None
    finally:
        _kill_process(process)
        try: os.remove(config_path)
        except: pass

def stage2_clash_scholar_test(nodes):
    logger.info(f"\n{'='*60}")
    logger.info(f"[阶段2/3] Google Scholar 学术访问验证 ({len(nodes)} 个节点)")
    logger.info(f"{'='*60}")
    passed = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_CLASH) as ex:
        futures = {ex.submit(test_node_with_clash_scholar, n): n for n in nodes}
        for future in tqdm(as_completed(futures), total=len(nodes), desc="Scholar验证"):
            try:
                res = future.result(timeout=25)
                if res:
                    passed.append(res)
                    if len(passed) >= MAX_NODES_LIMIT:
                        for f in futures: f.cancel()
                        break
            except: pass
            time.sleep(0.1)
    logger.info(f"✓ 阶段2完成: {len(passed)} 个节点通过学术验证")
    return passed

# ==================== 输出文件生成 ====================
def ensure_unique_names(nodes):
    counts, result = {}, []
    for node in nodes:
        name = node['name']
        if name in counts:
            counts[name] += 1
            node = dict(node); node['name'] = f"{name}_{counts[name]}"
        else:
            counts[name] = 1
        result.append(node)
    return result

def generate_clash_config(nodes, output_file):
    logger.info(f"生成 Clash 配置: {len(nodes)} 节点 → {output_file}")
    config = {
        'port': 7890, 'socks-port': 7891, 'mixed-port': 7892,
        'allow-lan': False, 'mode': 'rule', 'log-level': 'info',
        'dns': {
            'enable': True, 'enhanced-mode': 'fake-ip',
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
            {'name': 'PROXY', 'type': 'select', 'proxies': ['AUTO','FALLBACK','DIRECT'] + names},
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
        'GEOIP,CN,DIRECT', 'MATCH,PROXY'
    ]
    with open(output_file, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)
    logger.info(f"✓ 已写入: {output_file}")

def generate_v2ray_base64_subscription(nodes, output_file):
    logger.info(f"生成 V2Ray Base64 订阅: {len(nodes)} 节点 → {output_file}")
    uris = [uri for uri in (node_to_uri(n) for n in nodes) if uri]
    content = '\n'.join(uris)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(base64.b64encode(content.encode('utf-8')).decode('utf-8'))
    plain = output_file.replace('.txt', '_plain.txt')
    with open(plain, 'w', encoding='utf-8') as f:
        f.write(content)
    logger.info(f"✓ 写入完成: {output_file} | 明文: {plain} ({len(uris)} 个节点)")

def check_environment():
    logger.info("检查基础网络环境...")
    try:
        r = safe_request_get('https://www.google.com/generate_204', timeout=3, allow_redirects=False)
        if r.status_code == 204:
            print("\n" + "!" * 75)
            logger.warning("【特别警告】检测到当前测试机【在未挂代理下可直连 Google】！")
            logger.warning("请注意：在 GitHub Actions / 境外 VPS 环境下测出的节点缺少 GFW 过滤。")
            logger.warning("脚本将自动启用最严格的两轮淘汰和 Scholar 纯净度校验，最大程度保障可用性。")
            print("!" * 75 + "\n")
            time.sleep(2)
    except:
        logger.info("✓ 网络环境检测正常：本地网络直连阻断（符合境内严苛测试条件）。")

# ==================== 主流程 ====================
def main():
    logger.info("="*60)
    logger.info("Clash/V2Ray 节点深度清洗聚合测速工具 v2.3")
    logger.info("流程: 深度清洗去重 → 延迟初筛 → 真连接Google严格校验(×2) → Scholar学术验证")
    logger.info("="*60)

    check_environment()

    # 检查内核
    if STAGE1_V2RAY_TEST and not os.path.exists(V2RAY_BINARY_PATH):
        logger.warning(f"未找到 V2Ray 二进制文件 ({V2RAY_BINARY_PATH})，跳过阶段 1")
        globals()['STAGE1_V2RAY_TEST'] = False
    if not os.path.exists(CLASH_BINARY_PATH):
        logger.error(f"未找到 Clash 二进制文件: {CLASH_BINARY_PATH}")
        sys.exit(1)

    # 读取订阅链接
    if not os.path.exists(SUBSCRIPTION_URLS_FILE):
        with open(SUBSCRIPTION_URLS_FILE, 'w', encoding='utf-8') as f:
            f.write("# 在此处填入订阅URL，每行一个\n")
        logger.error(f"请在 {SUBSCRIPTION_URLS_FILE} 中填入订阅链接后重试"); return

    with open(SUBSCRIPTION_URLS_FILE, 'r', encoding='utf-8') as f:
        urls = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    if not urls:
        logger.warning("订阅列表为空"); return

    logger.info(f"读取到 {len(urls)} 个订阅源，正在抓取内容...")
    contents = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_FETCH) as ex:
        futures = {ex.submit(get_subscription_content, url): url for url in urls}
        for f in tqdm(as_completed(futures), total=len(futures), desc="抓取订阅"):
            url = futures[f]; content = f.result()
            if content: contents[url] = content

    if not contents:
        logger.error("所有订阅均抓取失败，退出程序"); return

    # 提取节点
    all_nodes = parse_all_nodes(contents)
    if not all_nodes:
        logger.warning("未解析到任何可用节点，退出程序"); return

    # ── 【核心步骤】：前置清洗与去重 ──
    # 将 70000+ 的海量重复/广告节点浓缩为 ~3000 个高质量候选节点
    clean_nodes = clean_and_deduplicate_nodes(all_nodes, max_limit=MAX_PRE_TEST_NODES)
    if not clean_nodes:
        logger.warning("清洗后无可测试节点"); return

    # ── 阶段1: 延迟初筛 ──
    if STAGE1_V2RAY_TEST:
        stage1_nodes = stage1_v2ray_test(clean_nodes)
    else:
        stage1_nodes = clean_nodes[:STAGE1_TOP_N]

    if not stage1_nodes:
        logger.warning("阶段1后无存活节点"); return

    # ── 阶段1.5: 真连接 Google 第1轮 ──
    real1_nodes = stage_real_google_test(stage1_nodes, pass_num=1) if STAGE15_REAL_TEST else stage1_nodes
    if not real1_nodes:
        logger.warning("真连接第1轮无节点通过"); return

    # ── 阶段1.7: 真连接 Google 第2轮 (排除偶然波动节点) ──
    real2_nodes = stage_real_google_test(real1_nodes, pass_num=2) if STAGE15_REAL_TEST else real1_nodes
    if not real2_nodes:
        logger.warning("真连接第2轮无节点通过"); return

    real2_nodes = ensure_unique_names(real2_nodes)

    # 输出基础可用配置文件 (Clash + V2Ray Base64)
    generate_clash_config(real2_nodes, OUTPUT_CLASH_FILE)
    generate_v2ray_base64_subscription(real2_nodes, OUTPUT_V2RAY_BASE64_FILE)

    with open(UPDATE_TIME_FILE, 'w', encoding='utf-8') as f:
        f.write(f"更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"原始抓取节点数: {len(all_nodes)}\n")
        f.write(f"清洗去重后送测: {len(clean_nodes)}\n")
        f.write(f"延迟初筛通过数: {len(stage1_nodes)}\n")
        f.write(f"Google真连接两轮通过: {len(real2_nodes)}\n")

    # ── 阶段2: Google Scholar 学术深度测试 ──
    if STAGE2_SCHOLAR_TEST:
        final_nodes = stage2_clash_scholar_test(real2_nodes)
        if final_nodes:
            final_nodes = ensure_unique_names(final_nodes)
            generate_clash_config(final_nodes, OUTPUT_CLASH_FILE_SCHOLAR)
            scholar_b64 = OUTPUT_V2RAY_BASE64_FILE.replace('.txt', '_scholar.txt')
            generate_v2ray_base64_subscription(final_nodes, scholar_b64)
            with open(UPDATE_TIME_FILE, 'a', encoding='utf-8') as f:
                f.write(f"Scholar可用节点数: {len(final_nodes)}\n")
            logger.info(f"\n全部流程完成！Scholar节点数量: {len(final_nodes)}")
            logger.info(f"  Clash配置: {OUTPUT_CLASH_FILE_SCHOLAR}")
            logger.info(f"  V2Ray Base64: {scholar_b64}")
        else:
            logger.warning("未检测到可通过 Google Scholar 验证的纯净节点")
            generate_clash_config([], OUTPUT_CLASH_FILE_SCHOLAR)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\n用户主动中断运行"); sys.exit(0)
    except Exception as e:
        logger.error(f"致命错误: {e}", exc_info=True); sys.exit(1)
