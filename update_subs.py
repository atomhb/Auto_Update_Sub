#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Clash/V2Ray 订阅聚合 & 节点测试工具 v2.1
支持协议: VMess, VLESS, Trojan, SS, SSR, Hysteria2, TUIC, AnyTLS
测试流程: 阶段1(V2Ray延迟) → 阶段1.5(真连接Google×2) → 阶段2(Scholar验证)
输出: Clash YAML + V2Ray Base64 订阅文件
"""

import base64, json, os, requests, socket, time, yaml
import subprocess, random, string, sys, logging
from datetime import datetime
from urllib.parse import unquote, urlparse, parse_qs, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import hashlib, urllib3

urllib3.disable_warnings()

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# ==================== 全局配置 ====================
SUBSCRIPTION_URLS_FILE   = 'sub_urls.txt'
OUTPUT_CLASH_FILE        = 'sub.yaml'
OUTPUT_CLASH_FILE_SCHOLAR= 'sub_scholar.yaml'
OUTPUT_V2RAY_BASE64_FILE = 'sub_v2ray_base64.txt'
UPDATE_TIME_FILE         = 'update_time.txt'

# 阶段开关
STAGE1_V2RAY_TEST    = True   # 阶段1: V2Ray延迟测试
STAGE1_TOP_N         = 2000   # 阶段1保留前N个节点
STAGE15_REAL_TEST    = True   # 阶段1.5/1.7: 真连接Google测试（两轮）
STAGE2_SCHOLAR_TEST  = True   # 阶段2: Scholar验证

# V2Ray配置
V2RAY_BINARY_PATH    = './v2ray'
V2RAY_TEST_TIMEOUT   = 3.0    # 阶段1延迟测试超时(秒)
REAL_TEST_TIMEOUT    = 8.0    # 真连接测试超时(秒)
REAL_TEST_URL        = 'https://www.google.com/generate_204'  # 真连接目标

# Clash配置
CLASH_BINARY_PATH    = './clash'
MAX_LATENCY_MS       = 500
MAX_NODES_LIMIT      = 500

# 并发控制
MAX_WORKERS_FETCH    = 20
MAX_WORKERS_V2RAY    = 50    # V2Ray测试并发
MAX_WORKERS_REAL     = 30    # 真连接测试并发（低于V2Ray，避免端口耗尽）
MAX_WORKERS_CLASH    = 8

# Scholar验证
SCHOLAR_VERIFY_URL   = 'https://scholar.google.com/scholar?q=test'

# ==================== HTTP Session ====================
_session = None
def get_session():
    global _session
    if _session is None:
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=60, pool_maxsize=120, max_retries=1)
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
    for k, v in {'udp': True, 'skip-cert-verify': False}.items():
        node.setdefault(k, v)
    if 'port' in node:
        node['port'] = int(node['port'])
    return {k: v for k, v in node.items() if v is not None and v != ''}

# ==================== 节点解析 ====================
def get_subscription_content(url):
    headers = {'User-Agent': 'ClashforWindows/0.20.39 clash-verge/1.7.7'}
    try:
        logger.info(f"获取订阅: {url[:80]}...")
        r = get_session().get(url, timeout=20, headers=headers, verify=False)
        r.raise_for_status()
        r.encoding = 'utf-8'
        return r.text
    except Exception as e:
        logger.error(f"获取失败 [{url[:50]}]: {e}")
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
    except Exception as e:
        logger.debug(f"VMess解析失败: {e}"); return None

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
        elif net == 'h2':
            h2 = {}
            if params.get('path'): h2['path'] = unquote(params['path'])
            if params.get('host'): h2['host'] = [params['host']]
            if h2: node['h2-opts'] = h2
        elif net == 'httpupgrade':
            hu = {}
            if params.get('path'): hu['path'] = unquote(params['path'])
            if params.get('host'): hu['host'] = params['host']
            if hu: node['httpupgrade-opts'] = hu
        if params.get('flow'): node['flow'] = params['flow']
        return standardize_node(node)
    except Exception as e:
        logger.debug(f"VLESS解析失败: {e}"); return None

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
        if params.get('fp'): node['client-fingerprint'] = params['fp']
        return standardize_node(node)
    except Exception as e:
        logger.debug(f"Trojan解析失败: {e}"); return None

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
        params = {k: v[0] for k, v in parse_qs(parts.query).items() if v}
        if params.get('plugin'):
            pi = params['plugin'].split(';')
            if 'obfs' in pi[0]:
                node['plugin'] = 'obfs'; node['plugin-opts'] = {}
                for opt in pi[1:]:
                    if '=' in opt:
                        k, v = opt.split('=', 1)
                        if k == 'obfs': node['plugin-opts']['mode'] = v
                        elif k == 'obfs-host': node['plugin-opts']['host'] = v
        return standardize_node(node)
    except Exception as e:
        logger.debug(f"SS解析失败: {e}"); return None

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
    except Exception as e:
        logger.debug(f"SSR解析失败: {e}"); return None

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
        for k in ['up', 'down', 'obfs', 'obfs-password']:
            if params.get(k): node[k] = params[k]
        return standardize_node(node)
    except Exception as e:
        logger.debug(f"Hysteria2解析失败: {e}"); return None

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
        if params.get('allow_insecure') in ['1', 'true'] or params.get('insecure') in ['1', 'true']:
            node['skip-cert-verify'] = True
        return standardize_node(node)
    except Exception as e:
        logger.debug(f"TUIC解析失败: {e}"); return None

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
        if params.get('alpn'): node['alpn'] = params['alpn'].split(',')
        if params.get('insecure') in ['1', 'true']: node['skip-cert-verify'] = True
        if params.get('fp'): node['client-fingerprint'] = params['fp']
        return standardize_node(node)
    except Exception as e:
        logger.debug(f"AnyTLS解析失败: {e}"); return None

# ==================== 节点序列化为URI ====================
def node_to_uri(node):
    t = node.get('type', '')
    try:
        if t == 'vmess':     return _vmess_uri(node)
        if t == 'vless':     return _vless_uri(node)
        if t == 'trojan':    return _trojan_uri(node)
        if t == 'ss':        return _ss_uri(node)
        if t == 'hysteria2': return _hysteria2_uri(node)
        if t == 'tuic':      return _tuic_uri(node)
        if t == 'anytls':    return _anytls_uri(node)
    except Exception as e:
        logger.debug(f"节点转URI失败 [{node.get('name')}]: {e}")
    return None

def _vmess_uri(n):
    data = {'v': '2', 'ps': n.get('name',''), 'add': n.get('server',''),
            'port': str(n.get('port','')), 'id': n.get('uuid',''),
            'aid': str(n.get('alterId',0)), 'scy': n.get('cipher','auto'),
            'net': n.get('network','tcp'), 'tls': 'tls' if n.get('tls') else '',
            'sni': n.get('servername',''), 'fp': n.get('client-fingerprint','')}
    for opt, key in [('ws-opts','ws'), ('h2-opts','h2')]:
        opts = n.get(opt, {})
        if opts:
            data['path'] = opts.get('path','/')
            h = opts.get('headers', opts.get('host', {}))
            data['host'] = (h[0] if isinstance(h, list) else h.get('Host','')) if h else ''
    if n.get('grpc-opts'):
        data['path'] = n['grpc-opts'].get('grpc-service-name','')
    return f"vmess://{base64.b64encode(json.dumps(data,ensure_ascii=False).encode()).decode()}"

def _vless_uri(n):
    p = {'type': n.get('network','tcp')}
    if n.get('tls'):
        p['security'] = 'reality' if n.get('reality-opts') else 'tls'
        if n.get('reality-opts'):
            ro = n['reality-opts']
            if ro.get('public-key'): p['pbk'] = ro['public-key']
            if ro.get('short-id'): p['sid'] = ro['short-id']
    if n.get('servername'): p['sni'] = n['servername']
    if n.get('client-fingerprint'): p['fp'] = n['client-fingerprint']
    if n.get('flow'): p['flow'] = n['flow']
    ws = n.get('ws-opts',{})
    if ws:
        if ws.get('path'): p['path'] = ws['path']
        if ws.get('headers',{}).get('Host'): p['host'] = ws['headers']['Host']
    grpc = n.get('grpc-opts',{})
    if grpc: p['serviceName'] = grpc.get('grpc-service-name','')
    q = '&'.join(f"{k}={quote(str(v))}" for k,v in p.items() if v)
    return f"vless://{n['uuid']}@{n['server']}:{n['port']}?{q}#{quote(n.get('name',''))}"

def _trojan_uri(n):
    p = {}
    if n.get('sni'): p['sni'] = n['sni']
    if n.get('network'): p['type'] = n['network']
    ws = n.get('ws-opts',{})
    if ws:
        if ws.get('path'): p['path'] = ws['path']
        if ws.get('headers',{}).get('Host'): p['host'] = ws['headers']['Host']
    if n.get('alpn'): p['alpn'] = ','.join(n['alpn'])
    if n.get('skip-cert-verify'): p['allowInsecure'] = '1'
    q = '&'.join(f"{k}={quote(str(v))}" for k,v in p.items() if v)
    return f"trojan://{quote(n['password'])}@{n['server']}:{n['port']}?{q}#{quote(n.get('name',''))}"

def _ss_uri(n):
    ui = base64.urlsafe_b64encode(f"{n['cipher']}:{n['password']}".encode()).decode().rstrip('=')
    return f"ss://{ui}@{n['server']}:{n['port']}#{quote(n.get('name',''))}"

def _hysteria2_uri(n):
    p = {}
    if n.get('sni'): p['sni'] = n['sni']
    if n.get('alpn'): p['alpn'] = ','.join(n['alpn'])
    if n.get('skip-cert-verify'): p['insecure'] = '1'
    for k in ['up','down','obfs','obfs-password']:
        if n.get(k): p[k] = n[k]
    q = '&'.join(f"{k}={quote(str(v))}" for k,v in p.items() if v)
    qs = f"?{q}" if q else ''
    return f"hysteria2://{quote(n['password'])}@{n['server']}:{n['port']}{qs}#{quote(n.get('name',''))}"

def _tuic_uri(n):
    p = {}
    if n.get('sni'): p['sni'] = n['sni']
    if n.get('alpn'): p['alpn'] = ','.join(n['alpn'])
    if n.get('congestion-controller'): p['congestion_control'] = n['congestion-controller']
    if n.get('udp-relay-mode'): p['udp_relay_mode'] = n['udp-relay-mode']
    if n.get('skip-cert-verify'): p['allow_insecure'] = '1'
    q = '&'.join(f"{k}={quote(str(v))}" for k,v in p.items() if v)
    qs = f"?{q}" if q else ''
    return f"tuic://{quote(n['uuid'])}:{quote(n['password'])}@{n['server']}:{n['port']}{qs}#{quote(n.get('name',''))}"

def _anytls_uri(n):
    p = {}
    if n.get('sni'): p['sni'] = n['sni']
    if n.get('alpn'): p['alpn'] = ','.join(n['alpn'])
    if n.get('skip-cert-verify'): p['insecure'] = '1'
    if n.get('client-fingerprint'): p['fp'] = n['client-fingerprint']
    q = '&'.join(f"{k}={quote(str(v))}" for k,v in p.items() if v)
    qs = f"?{q}" if q else ''
    return f"anytls://{quote(n['password'])}@{n['server']}:{n['port']}{qs}#{quote(n.get('name',''))}"

# ==================== 解析总入口 ====================
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
        if nodes: logger.info(f"  └─ {len(nodes)} 个节点 ({url[:60]})")
    logger.info(f"总解析: {len(all_nodes)} 个唯一节点")
    return all_nodes

def validate_clash_node(node):
    if not all(f in node for f in ['name','type','server','port']): return False
    t = node['type']
    if t == 'vmess':     return 'uuid' in node and 'alterId' in node
    if t == 'vless':     return 'uuid' in node
    if t in ('trojan','ss','hysteria2','anytls'): return 'password' in node
    if t == 'tuic':      return 'uuid' in node and 'password' in node
    return True

# ==================== V2Ray进程管理 ====================
def _start_v2ray(node, socks_port, http_port):
    """启动V2Ray进程，返回(process, config_path)"""
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
        if node.get('network') == 'ws' and node.get('ws-opts'):
            wo = node['ws-opts']
            ob['streamSettings']['wsSettings'] = {
                'path': wo.get('path','/'), 'headers': wo.get('headers',{})}
        config['outbounds'] = [ob]

    elif t == 'vless':
        ob = {
            "protocol": "vless",
            "settings": {"vnext": [{"address": node['server'], "port": node['port'],
                "users": [{"id": node['uuid'], "encryption": "none",
                           "flow": node.get('flow','')}]}]},
            "streamSettings": {"network": node.get('network','tcp')}
        }
        if node.get('tls'):
            ob['streamSettings']['security'] = 'tls'
            ob['streamSettings']['tlsSettings'] = {
                'serverName': node.get('servername',''),
                'allowInsecure': node.get('skip-cert-verify', False)
            }
        if node.get('network') == 'ws' and node.get('ws-opts'):
            wo = node['ws-opts']
            ob['streamSettings']['wsSettings'] = {
                'path': wo.get('path','/'), 'headers': wo.get('headers',{})}
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
        try: process.terminate(); process.wait(timeout=2)
        except:
            try: process.kill()
            except: pass

# ==================== 阶段1: V2Ray延迟测试 ====================
def test_node_with_v2ray(node):
    """阶段1: 快速延迟测试（gstatic 204），Hy2/TUIC/AnyTLS直通"""
    if node['type'] in ('hysteria2', 'tuic', 'anytls'):
        return 0  # 直通，后续由Clash测试

    socks_port, http_port = get_free_port(), get_free_port()
    process, config_path = None, None
    try:
        process, config_path = _start_v2ray(node, socks_port, http_port)
        time.sleep(1.2)
        proxies = {'http': f'http://127.0.0.1:{http_port}',
                   'https': f'http://127.0.0.1:{http_port}'}
        start = time.time()
        r = get_session().get('https://www.gstatic.com/generate_204',
                              proxies=proxies, timeout=V2RAY_TEST_TIMEOUT, verify=False)
        if r.status_code in [200, 204]:
            delay = round((time.time() - start) * 1000)
            logger.info(f"✓ V2ray延迟 {node['name']}: {delay}ms")
            return delay
    except: pass
    finally:
        _kill_process(process)
        try: os.remove(config_path)
        except: pass
    return -1

def stage1_v2ray_test(nodes):
    logger.info(f"\n{'='*60}")
    logger.info(f"[阶段1/3] V2Ray延迟快速筛选 ({len(nodes)} 个节点)")
    logger.info(f"{'='*60}")
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_V2RAY) as ex:
        futures = {ex.submit(test_node_with_v2ray, n): n for n in nodes}
        for future in tqdm(as_completed(futures), total=len(nodes), desc="V2Ray延迟"):
            node = futures[future]
            try:
                delay = future.result(timeout=V2RAY_TEST_TIMEOUT + 8)
                if delay >= 0:
                    results.append({'node': node, 'delay': delay if delay > 0 else 9999})
            except: pass
    results.sort(key=lambda x: x['delay'])
    top = results[:STAGE1_TOP_N]
    logger.info(f"✓ 阶段1完成: {len(top)}/{len(nodes)} 个节点通过延迟筛选")
    return [x['node'] for x in top]

# ==================== 阶段1.5/1.7: 真连接 Google 测试 ====================
def _test_real_google_v2ray(node):
    """通过V2Ray代理真实访问 www.google.com/generate_204，返回延迟ms或-1"""
    socks_port, http_port = get_free_port(), get_free_port()
    process, config_path = None, None
    try:
        process, config_path = _start_v2ray(node, socks_port, http_port)
        time.sleep(1.5)  # 稍长等待，确保连接稳定
        proxies = {'http': f'http://127.0.0.1:{http_port}',
                   'https': f'http://127.0.0.1:{http_port}'}
        start = time.time()
        r = requests.get(REAL_TEST_URL, proxies=proxies,
                         timeout=REAL_TEST_TIMEOUT, verify=False,
                         headers={'User-Agent': 'Mozilla/5.0'})
        if r.status_code in [200, 204]:
            delay = round((time.time() - start) * 1000)
            logger.info(f"✓ 真连接[Google] {node['name']}: {delay}ms")
            return delay
    except: pass
    finally:
        _kill_process(process)
        try: os.remove(config_path)
        except: pass
    return -1

def _test_real_google_clash(node):
    """通过Clash代理真实访问 www.google.com/generate_204（用于Hy2/TUIC/AnyTLS）"""
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
        if not _wait_for_clash_api(f'127.0.0.1:{api_port}', timeout=10):
            return -1
        proxies = {'http': f'socks5h://127.0.0.1:{socks_port}',
                   'https': f'socks5h://127.0.0.1:{socks_port}'}
        start = time.time()
        r = requests.get(REAL_TEST_URL, proxies=proxies,
                         timeout=REAL_TEST_TIMEOUT, verify=False,
                         headers={'User-Agent': 'Mozilla/5.0'})
        if r.status_code in [200, 204]:
            delay = round((time.time() - start) * 1000)
            logger.info(f"✓ 真连接[Google/Clash] {node['name']}: {delay}ms")
            return delay
    except: pass
    finally:
        _kill_process(process)
        try: os.remove(config_path)
        except: pass
        time.sleep(0.2)
    return -1

def test_real_google(node):
    """统一真连接测试入口：V2Ray协议用V2Ray，其他用Clash"""
    if node['type'] in ('hysteria2', 'tuic', 'anytls'):
        return _test_real_google_clash(node)
    return _test_real_google_v2ray(node)

def stage_real_google_test(nodes, pass_num=1):
    """
    真连接测试阶段（可执行两轮）
    pass_num=1: 阶段1.5 — 排除无法访问Google的节点
    pass_num=2: 阶段1.7 — 再次验证，排除不稳定节点
    """
    label = f"阶段1.{pass_num*2+3}/3" if pass_num == 2 else "阶段1.5/3"
    logger.info(f"\n{'='*60}")
    logger.info(f"[{label}] 真连接 Google 测试 第{pass_num}轮 ({len(nodes)} 个节点)")
    logger.info(f"  目标: {REAL_TEST_URL}")
    logger.info(f"{'='*60}")

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_REAL) as ex:
        futures = {ex.submit(test_real_google, n): n for n in nodes}
        for future in tqdm(as_completed(futures), total=len(nodes),
                           desc=f"真连接Google[第{pass_num}轮]"):
            node = futures[future]
            try:
                delay = future.result(timeout=REAL_TEST_TIMEOUT + 12)
                if delay > 0:
                    results.append({'node': node, 'delay': delay})
            except: pass

    results.sort(key=lambda x: x['delay'])
    passed = [x['node'] for x in results]
    logger.info(f"✓ 真连接第{pass_num}轮完成: {len(passed)}/{len(nodes)} 个节点可访问Google")
    return passed

# ==================== 阶段2: Clash Scholar验证 ====================
def _wait_for_clash_api(api_addr, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(f'http://{api_addr}/version', timeout=1)
            if r.status_code == 200: return True
        except: pass
        time.sleep(0.3)
    return False

def verify_scholar_access(socks_address, node_name):
    if not STAGE2_SCHOLAR_TEST: return True
    try:
        proxies = {'http': f'socks5h://{socks_address}',
                   'https': f'socks5h://{socks_address}'}
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
                   'Accept-Language': 'en-US,en;q=0.9'}
        r = requests.get(SCHOLAR_VERIFY_URL, proxies=proxies, timeout=15,
                         headers=headers, verify=False)
        if r.status_code == 200:
            cl = r.text.lower()
            blocked = any(kw in cl for kw in ['captcha','automated queries','/sorry/index','unusual traffic'])
            if not blocked:
                logger.info(f"✓ Scholar可访问: {node_name}"); return True
            logger.warning(f"✗ Scholar受限(验证码): {node_name}")
        else:
            logger.debug(f"✗ Scholar状态码{r.status_code}: {node_name}")
    except Exception as e:
        logger.debug(f"Scholar异常 [{node_name}]: {e}")
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
        if not _wait_for_clash_api(f'127.0.0.1:{api_port}', timeout=10):
            return None
        return node if verify_scholar_access(f'127.0.0.1:{socks_port}', node['name']) else None
    except Exception as e:
        logger.debug(f"Clash Scholar失败 {node['name']}: {e}"); return None
    finally:
        _kill_process(process)
        try: os.remove(config_path)
        except: pass
        time.sleep(0.2)

def stage2_clash_scholar_test(nodes):
    logger.info(f"\n{'='*60}")
    logger.info(f"[阶段2/3] Clash + Google Scholar验证 ({len(nodes)} 个节点)")
    logger.info(f"{'='*60}")
    valid = [n for n in nodes if validate_clash_node(n)]
    logger.info(f"格式验证: {len(valid)}/{len(nodes)} 个节点有效")
    if not valid: return []
    passed = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_CLASH) as ex:
        futures = {ex.submit(test_node_with_clash_scholar, n): n for n in valid}
        for future in tqdm(as_completed(futures), total=len(valid), desc="Scholar验证"):
            try:
                result = future.result(timeout=35)
                if result:
                    passed.append(result)
                    if len(passed) >= MAX_NODES_LIMIT:
                        for f in futures: f.cancel()
                        break
            except: pass
            time.sleep(random.uniform(0.3, 0.6))
    logger.info(f"✓ 阶段2完成: {len(passed)} 个节点通过Scholar验证")
    return passed

# ==================== 输出 ====================
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
    logger.info(f"生成Clash配置: {len(nodes)} 节点 → {output_file}")
    config = {
        'port': 7890, 'socks-port': 7891, 'mixed-port': 7892,
        'allow-lan': False, 'mode': 'rule', 'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'dns': {
            'enabled': True, 'enhanced-mode': 'fake-ip',
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
    logger.info(f"生成V2Ray Base64订阅: {len(nodes)} 节点 → {output_file}")
    uris = [uri for uri in (node_to_uri(n) for n in nodes) if uri]
    content = '\n'.join(uris)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(base64.b64encode(content.encode('utf-8')).decode('utf-8'))
    plain = output_file.replace('.txt', '_plain.txt')
    with open(plain, 'w', encoding='utf-8') as f:
        f.write(content)
    logger.info(f"✓ V2Ray Base64: {output_file} | 明文: {plain} ({len(uris)} 节点)")

# ==================== 主流程 ====================
def main():
    logger.info("="*60)
    logger.info("节点聚合测试工具 v2.1")
    logger.info("流程: V2Ray延迟 → 真连接Google×2 → Scholar验证")
    logger.info("="*60)

    # 检查依赖
    if STAGE1_V2RAY_TEST and not os.path.exists(V2RAY_BINARY_PATH):
        logger.warning(f"V2ray未找到({V2RAY_BINARY_PATH})，跳过阶段1")
        globals()['STAGE1_V2RAY_TEST'] = False
    if not os.path.exists(CLASH_BINARY_PATH):
        logger.error(f"Clash未找到: {CLASH_BINARY_PATH}")
        logger.info("下载: https://github.com/MetaCubeX/mihomo/releases")
        sys.exit(1)

    # 读取订阅URL
    if not os.path.exists(SUBSCRIPTION_URLS_FILE):
        with open(SUBSCRIPTION_URLS_FILE, 'w', encoding='utf-8') as f:
            f.write("# 每行一个订阅URL\n")
        logger.error(f"请在 {SUBSCRIPTION_URLS_FILE} 中添加订阅"); return

    with open(SUBSCRIPTION_URLS_FILE, 'r', encoding='utf-8') as f:
        urls = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    if not urls:
        logger.warning("无有效订阅链接"); return
    logger.info(f"订阅数: {len(urls)}")

    # 并发获取订阅
    logger.info("\n获取订阅内容...")
    contents = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_FETCH) as ex:
        futures = {ex.submit(get_subscription_content, url): url for url in urls}
        for f in tqdm(as_completed(futures), total=len(futures), desc="获取订阅"):
            url = futures[f]; content = f.result()
            if content: contents[url] = content
    logger.info(f"成功: {len(contents)}/{len(urls)} 个订阅")
    if not contents:
        logger.error("所有订阅获取失败"); return

    # 解析节点
    all_nodes = parse_all_nodes(contents)
    if not all_nodes:
        logger.warning("未解析到节点"); return

    # ── 阶段1: V2Ray延迟筛选 ──
    if STAGE1_V2RAY_TEST:
        stage1_nodes = stage1_v2ray_test(all_nodes)
    else:
        stage1_nodes = all_nodes[:STAGE1_TOP_N]
        logger.info(f"跳过V2ray延迟测试，使用前{len(stage1_nodes)}个节点")

    if not stage1_nodes:
        logger.warning("阶段1无节点"); return

    # ── 阶段1.5: 真连接Google第1轮 ──
    if STAGE15_REAL_TEST:
        real1_nodes = stage_real_google_test(stage1_nodes, pass_num=1)
    else:
        real1_nodes = stage1_nodes

    if not real1_nodes:
        logger.warning("真连接第1轮无节点通过"); return

    # ── 阶段1.7: 真连接Google第2轮（排除不稳定节点）──
    if STAGE15_REAL_TEST:
        real2_nodes = stage_real_google_test(real1_nodes, pass_num=2)
    else:
        real2_nodes = real1_nodes

    if not real2_nodes:
        logger.warning("真连接第2轮无节点通过"); return

    real2_nodes = ensure_unique_names(real2_nodes)

    # 输出真连接通过后的文件
    generate_clash_config(real2_nodes, OUTPUT_CLASH_FILE)
    generate_v2ray_base64_subscription(real2_nodes, OUTPUT_V2RAY_BASE64_FILE)

    with open(UPDATE_TIME_FILE, 'w', encoding='utf-8') as f:
        f.write(f"更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"总解析节点: {len(all_nodes)}\n")
        f.write(f"V2Ray延迟通过: {len(stage1_nodes)}\n")
        f.write(f"真连接第1轮通过: {len(real1_nodes)}\n")
        f.write(f"真连接第2轮通过: {len(real2_nodes)}\n")
        f.write(f"订阅来源: {len(contents)}\n")

    # ── 阶段2: Clash Scholar验证 ──
    final_nodes = stage2_clash_scholar_test(real2_nodes)

    if final_nodes:
        final_nodes = ensure_unique_names(final_nodes)
        generate_clash_config(final_nodes, OUTPUT_CLASH_FILE_SCHOLAR)
        scholar_b64 = OUTPUT_V2RAY_BASE64_FILE.replace('.txt', '_scholar.txt')
        generate_v2ray_base64_subscription(final_nodes, scholar_b64)
        with open(UPDATE_TIME_FILE, 'a', encoding='utf-8') as f:
            f.write(f"Scholar验证通过: {len(final_nodes)}\n")
        logger.info(f"\n{'='*60}")
        logger.info(f"✓ 全部完成！Scholar可用节点: {len(final_nodes)}")
        logger.info(f"  Clash:   {OUTPUT_CLASH_FILE_SCHOLAR}")
        logger.info(f"  V2Ray:   {scholar_b64}")
        logger.info(f"{'='*60}")
    else:
        logger.warning("Scholar验证无可用节点")
        generate_clash_config([], OUTPUT_CLASH_FILE_SCHOLAR)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\n用户中断"); sys.exit(0)
    except Exception as e:
        logger.error(f"运行错误: {e}", exc_info=True); sys.exit(1)
