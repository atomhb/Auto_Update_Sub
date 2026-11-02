#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Clash/V2Ray 订阅聚合 & 节点深度过滤工具 
支持协议: VMess, VLESS (含 Reality), Trojan, SS, SSR, Hysteria2, TUIC, AnyTLS
核心修复与升级:
  1. 修复致命直连泄漏: 强制 Clash 测试配置绑定 proxy-groups 与 MATCH 规则，杜绝默认走 DIRECT
  2. 出口 IP 铁证校验: 通过 Cloudflare Trace 校验代理出口 IP != 本机 IP，且剔除 CN (境内回国) 出口节点
  3. 真实内容载荷校验: 废除单纯的 204 空包检测，强制下载 Google robots.txt 并校验正文特征，彻底消灭假 204 与 0 带宽死节点
  4. 全协议统一引擎: 阶段1改用 Mihomo (Clash) 批量并发 API 测速，完美支持 Reality/Hy2/TUIC/WS/gRPC，速度提升 8 倍
  5. 完整 URI 序列化: 修复导出 V2Ray Base64 订阅时丢失 ws-opts/grpc-opts/reality/fp/sni 的严重 Bug
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
import uuid as uuid_lib
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
MAX_PRE_TEST_NODES        = 15000   # 前置清洗后允许进入测速的最大节点上限
MAX_PER_CDN_BACKEND       = 2       # 同一 CDN 后端 (相同 UUID+SNI/Host) 最多保留优选 IP 数
MAX_PER_SERVER_IP         = 2       # 同一服务器 IP 最多保留的不同端口节点数

# 测速阶段开关与参数
STAGE1_V2RAY_TEST         = True    # 阶段1: 延迟初筛 (已升级为 Mihomo 全协议批量并发初筛)
STAGE1_TOP_N              = 1200    # 阶段1保留前 N 个低延迟节点
STAGE15_REAL_TEST         = True    # 阶段1.5 & 1.7: 真连接内容与出口 IP 严苛校验 (两轮)
STAGE2_SCHOLAR_TEST       = True    # 阶段2: Google Scholar 学术免验证码测试

# 核心可执行文件路径
V2RAY_BINARY_PATH         = './v2ray'
CLASH_BINARY_PATH         = './clash'

V2RAY_TEST_TIMEOUT        = 3.5     # 初筛延迟测试超时(秒)
REAL_TEST_TIMEOUT         = 6.0     # 真连接内容测试超时(秒)

# 真实性校验目标
TRACE_TEST_URL            = 'https://www.cloudflare.com/cdn-cgi/trace'
GOOGLE_ROBOTS_URL         = 'https://www.google.com/robots.txt'
GOOGLE_204_URL            = 'https://www.google.com/generate_204'
GSTATIC_204_URL           = 'https://www.gstatic.com/generate_204'
SCHOLAR_VERIFY_URL        = 'https://scholar.google.com/scholar?q=machine+learning&hl=en'

# 并发控制
STAGE1_BATCH_SIZE         = 80      # 阶段1每个 Clash 实例挂载的节点批次大小
STAGE1_API_CONCURRENCY    = 40      # 阶段1 API 并发测速线程数
REAL_WORKER_BATCH_SIZE    = 20      # 阶段1.5/2 每个 Clash 工作进程轮询测试的节点数
MAX_WORKERS_FETCH         = 20
MAX_WORKERS_REAL          = 12      # 阶段1.5 并行 Clash 进程数
MAX_WORKERS_CLASH         = 8       # 阶段2 并行 Clash 进程数
MAX_NODES_LIMIT           = 500     # 最终保留的最大节点数

# 本机公网 IP (用于防直连泄漏比对)
LOCAL_PUBLIC_IP           = None

# 合法的 SS 加密方式白名单 (防止畸形加密导致 Clash 进程崩溃)
VALID_SS_CIPHERS = {
    'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
    'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
    '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305',
    'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
    'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
    'rc4-md5', 'chacha20', 'chacha20-ietf'
}

VALID_VMESS_CIPHERS = {'auto', 'aes-128-gcm', 'chacha20-poly1305', 'none', 'zero'}

# 广告与无效节点关键词过滤列表
AD_KEYWORDS = [
    '剩余', '到期', '过期', '官网', '通知', '群', 'tg', 'channel', 'http',
    '更新', '重置', '套餐', '维护', '公告', '返利', '购买', '注册', '广告',
    '网址', '客服', '备用', '说明', '规则', '流量', '时间', '订阅', '防失联',
    '失联', '测试', '禁止', '福利', '机场', '邀请', '教程', '客户端'
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
    1. 强制 trust_env=False 杜绝环境变量代理污染
    2. 默认禁止重定向，杜绝伪造 302/200 劫持页
    """
    default_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept-Encoding': 'gzip, deflate'
    }
    if headers:
        default_headers.update(headers)
    with requests.Session() as s:
        s.trust_env = False
        return s.get(
            url, proxies=proxies, timeout=timeout, verify=False,
            allow_redirects=allow_redirects, headers=default_headers
        )


def safe_request_put(url, json_data=None, timeout=3):
    with requests.Session() as s:
        s.trust_env = False
        return s.put(url, json=json_data, timeout=timeout, verify=False)


# ==================== 基础工具与格式校验 ====================
def random_string(length=6):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]


def is_valid_uuid(val):
    try:
        uuid_lib.UUID(str(val))
        return True
    except:
        return False


def node_hash(node):
    sni = node.get('servername') or node.get('sni') or ''
    path = ''
    if isinstance(node.get('ws-opts'), dict):
        path = node['ws-opts'].get('path', '')
    elif isinstance(node.get('grpc-opts'), dict):
        path = node['grpc-opts'].get('grpc-service-name', '')
    cred = node.get('uuid') or node.get('password') or ''
    key = f"{node.get('type')}:{str(node.get('server')).lower()}:{node.get('port')}:{cred}:{sni}:{path}"
    return hashlib.md5(key.encode('utf-8', errors='ignore')).hexdigest()


def standardize_node(node):
    """
    严格标准化并校验节点合法性，剔除会导致 Clash/Mihomo 崩溃的畸形参数
    """
    if not isinstance(node, dict):
        return None

    ntype = str(node.get('type', '')).lower().strip()
    if ntype not in ('vmess', 'vless', 'trojan', 'ss', 'ssr', 'hysteria2', 'tuic', 'anytls'):
        return None
    node['type'] = ntype

    # 校验 Server
    server = str(node.get('server', '')).strip()
    if not server or ' ' in server or ':' in server and not server.startswith('['):
        # 若是未包裹的 IPv6 地址则尝试校验
        try:
            ipaddress.ip_address(server)
        except ValueError:
            if ':' in server or '/' in server:
                return None
    node['server'] = server

    # 校验 Port
    try:
        port = int(node.get('port', 0))
        if not (1 <= port <= 65535):
            return None
        node['port'] = port
    except:
        return None

    # 清理节点名称中的控制字符
    raw_name = str(node.get('name', f"{ntype}_{server}")).strip()
    clean_name = ''.join(ch for ch in raw_name if ch.isprintable()).strip()
    node['name'] = clean_name or f"{ntype}_{server}:{port}"

    # 协议特定字段严格校验
    if ntype == 'vmess':
        if not is_valid_uuid(node.get('uuid')):
            return None
        cipher = str(node.get('cipher', 'auto')).lower()
        node['cipher'] = cipher if cipher in VALID_VMESS_CIPHERS else 'auto'
        try:
            node['alterId'] = int(node.get('alterId', 0))
        except:
            node['alterId'] = 0

    elif ntype == 'vless':
        if not is_valid_uuid(node.get('uuid')):
            return None
        if node.get('reality-opts'):
            ro = node['reality-opts']
            if not isinstance(ro, dict) or not ro.get('public-key'):
                return None
            # Reality 协议在 Mihomo 中必须指定 client-fingerprint
            if not node.get('client-fingerprint'):
                node['client-fingerprint'] = 'chrome'

    elif ntype == 'trojan':
        pwd = str(node.get('password', '')).strip()
        if not pwd:
            return None
        node['password'] = pwd

    elif ntype == 'ss':
        cipher = str(node.get('cipher', '')).lower().strip()
        pwd = str(node.get('password', '')).strip()
        if cipher not in VALID_SS_CIPHERS or not pwd:
            return None
        node['cipher'] = cipher
        node['password'] = pwd

    elif ntype == 'hysteria2':
        pwd = str(node.get('password', '')).strip()
        if not pwd:
            return None
        node['password'] = pwd

    elif ntype == 'tuic':
        if not is_valid_uuid(node.get('uuid')) or node.get('password') is None:
            return None

    elif ntype == 'anytls':
        if not node.get('password'):
            return None

    node.setdefault('udp', True)
    node.setdefault('skip-cert-verify', False)

    return {k: v for k, v in node.items() if v is not None and v != ''}


# ==================== 节点深度清洗与去重 ====================
def is_junk_node(node):
    name = str(node.get('name', '')).lower()
    server = str(node.get('server', '')).strip().lower()
    port = node.get('port', 0)

    if not (1 <= port <= 65535):
        return True

    # 屏蔽常见高危或非代理端口 (如 22 SSH, 25 SMTP)
    if port in (21, 22, 23, 25, 53, 110, 143, 3306, 5432, 6379):
        return True

    for kw in AD_KEYWORDS:
        if kw in name:
            return True

    if server in ('127.0.0.1', 'localhost', '0.0.0.0', '1.1.1.1', '8.8.8.8'):
        return True

    try:
        ip = ipaddress.ip_address(server)
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local or ip.is_multicast:
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
    logger.info(f"1. 广告与非法参数过滤: 剔除 {len(nodes) - len(valid_nodes)} 个，保留有效节点 {len(valid_nodes)}")

    # 2. 严格特征去重 (type + server + port + credential)
    unique_exact = []
    exact_set = set()
    for n in valid_nodes:
        key = node_hash(n)
        if key not in exact_set:
            exact_set.add(key)
            unique_exact.append(n)
    logger.info(f"2. 精确特征去重: 剔除重复 {len(valid_nodes) - len(unique_exact)} 个，剩余 {len(unique_exact)}")

    # 3. CDN 优选 IP 轰炸收敛
    cdn_clusters = {}
    non_cdn_nodes = []
    for n in unique_exact:
        sni = n.get('servername') or n.get('sni') or ''
        host = n.get('ws-opts', {}).get('headers', {}).get('Host', '') if isinstance(n.get('ws-opts'), dict) else ''
        path = n.get('ws-opts', {}).get('path', '') if isinstance(n.get('ws-opts'), dict) else ''
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
        logger.warning(f"⚠️ 节点数仍有 {len(final_nodes)} 个，随机截取 {max_limit} 个送入测试阶段")
        final_nodes = final_nodes[:max_limit]

    logger.info(f"✓ 预处理完成！最终送测候选节点数: {len(final_nodes)}\n")
    return final_nodes


# ==================== 节点协议解析 ====================
def get_subscription_content(url):
    headers = {'User-Agent': 'ClashforWindows/0.20.39 clash-verge/1.7.7 Mihomo/1.18.0'}
    try:
        r = safe_request_get(url, timeout=15, allow_redirects=True, headers=headers)
        r.raise_for_status()
        r.encoding = 'utf-8'
        return r.text
    except Exception as e:
        logger.error(f"获取订阅失败 [{url[:45]}]: {e}")
        return None


def decode_base64_content(content):
    try:
        content = content.strip().replace('-', '+').replace('_', '/')
        padding = (4 - len(content) % 4) % 4
        return base64.b64decode((content + '=' * padding).encode('ascii')).decode('utf-8', errors='ignore')
    except:
        return None


def parse_node(link):
    link = link.strip()
    if not link:
        return None
    if link.startswith('vmess://'):
        return parse_vmess_link(link)
    if link.startswith('vless://'):
        return parse_vless_link(link)
    if link.startswith('trojan://'):
        return parse_trojan_link(link)
    if link.startswith('ss://'):
        return parse_ss_link(link)
    if link.startswith('ssr://'):
        return parse_ssr_link(link)
    if link.startswith('hysteria2://') or link.startswith('hy2://'):
        return parse_hysteria2_link(link)
    if link.startswith('tuic://'):
        return parse_tuic_link(link)
    if link.startswith('anytls://'):
        return parse_anytls_link(link)
    return None


def parse_vmess_link(link):
    try:
        b64 = link[8:].strip()
        raw_json = decode_base64_content(b64)
        if not raw_json:
            return None
        data = json.loads(raw_json)
        if not all(k in data for k in ['add', 'port', 'id']):
            return None
        tls_val = str(data.get('tls', '')).lower()
        node = {
            'name': (data.get('ps') or f"vmess_{data['add']}").strip(),
            'type': 'vmess',
            'server': str(data['add']).strip(),
            'port': int(data['port']),
            'uuid': str(data['id']).strip(),
            'alterId': int(data.get('aid', 0) or 0),
            'cipher': data.get('scy', 'auto') or 'auto',
            'tls': tls_val in ('tls', '1', 'true'),
            'network': str(data.get('net', 'tcp') or 'tcp').lower()
        }
        net = node['network']
        path = data.get('path', '')
        host = data.get('host', '')
        if net == 'ws':
            ws = {'path': path or '/'}
            if host:
                ws['headers'] = {'Host': host}
            node['ws-opts'] = ws
        elif net == 'h2':
            h2 = {'path': path or '/'}
            if host:
                h2['host'] = [h.strip() for h in host.split(',') if h.strip()]
            node['h2-opts'] = h2
        elif net == 'grpc':
            if path:
                node['grpc-opts'] = {'grpc-service-name': path}
        elif net == 'httpupgrade':
            hu = {'path': path or '/'}
            if host:
                hu['host'] = host
            node['httpupgrade-opts'] = hu

        sni = data.get('sni') or (host if node['tls'] else '')
        if node['tls'] and sni:
            node['servername'] = sni
        if data.get('fp'):
            node['client-fingerprint'] = data['fp']
        if data.get('alpn'):
            node['alpn'] = [a.strip() for a in str(data['alpn']).split(',') if a.strip()]
        return standardize_node(node)
    except:
        return None


def parse_vless_link(link):
    try:
        parts = urlparse(link)
        if '@' not in parts.netloc:
            return None
        uuid, host_info = parts.netloc.split('@', 1)
        if host_info.startswith('['):
            idx = host_info.index(']')
            server, port = host_info[1:idx], host_info[idx+2:]
        else:
            server, port = host_info.rsplit(':', 1)

        params = {k: v[0] for k, v in parse_qs(parts.query).items() if v}
        security = params.get('security', '').lower()
        node = {
            'name': unquote(parts.fragment).strip() if parts.fragment else f"vless_{server}",
            'type': 'vless',
            'server': server,
            'port': int(port),
            'uuid': unquote(uuid).strip(),
            'network': params.get('type', 'tcp').lower(),
            'tls': security in ('tls', 'reality')
        }
        if security == 'reality':
            ro = {}
            if params.get('pbk'):
                ro['public-key'] = params['pbk']
            if params.get('sid'):
                ro['short-id'] = params['sid']
            node['reality-opts'] = ro
            node['client-fingerprint'] = params.get('fp', 'chrome')
        if node['tls']:
            sni = params.get('sni') or params.get('host', '')
            if sni:
                node['servername'] = sni
            if params.get('fp'):
                node['client-fingerprint'] = params['fp']
            if params.get('allowInsecure') in ('1', 'true'):
                node['skip-cert-verify'] = True
            if params.get('alpn'):
                node['alpn'] = [a.strip() for a in unquote(params['alpn']).split(',') if a.strip()]

        net = node['network']
        if net == 'ws':
            ws = {'path': unquote(params.get('path', '/'))}
            if params.get('host'):
                ws['headers'] = {'Host': unquote(params['host'])}
            node['ws-opts'] = ws
        elif net == 'grpc':
            sn = params.get('serviceName') or params.get('path', '')
            if sn:
                node['grpc-opts'] = {'grpc-service-name': unquote(sn)}
        elif net == 'httpupgrade':
            hu = {'path': unquote(params.get('path', '/'))}
            if params.get('host'):
                hu['host'] = unquote(params['host'])
            node['httpupgrade-opts'] = hu

        if params.get('flow'):
            node['flow'] = params['flow']
        return standardize_node(node)
    except:
        return None


def parse_trojan_link(link):
    try:
        parts = urlparse(link)
        if '@' not in parts.netloc:
            return None
        password, host_info = parts.netloc.split('@', 1)
        if host_info.startswith('['):
            idx = host_info.index(']')
            server, port = host_info[1:idx], host_info[idx+2:]
        else:
            server, port = host_info.rsplit(':', 1)

        params = {k: v[0] for k, v in parse_qs(parts.query).items() if v}
        node = {
            'name': unquote(parts.fragment).strip() if parts.fragment else f"trojan_{server}",
            'type': 'trojan',
            'server': server,
            'port': int(port),
            'password': unquote(password),
            'sni': params.get('sni') or params.get('peer') or params.get('host') or server
        }
        net = params.get('type', 'tcp').lower()
        if net == 'ws':
            node['network'] = 'ws'
            ws = {'path': unquote(params.get('path', '/'))}
            if params.get('host'):
                ws['headers'] = {'Host': unquote(params['host'])}
            node['ws-opts'] = ws
        elif net == 'grpc':
            node['network'] = 'grpc'
            sn = params.get('serviceName') or params.get('path', '')
            if sn:
                node['grpc-opts'] = {'grpc-service-name': unquote(sn)}

        if params.get('alpn'):
            node['alpn'] = [a.strip() for a in unquote(params['alpn']).split(',') if a.strip()]
        if params.get('fp'):
            node['client-fingerprint'] = params['fp']
        if params.get('allowInsecure') in ('1', 'true'):
            node['skip-cert-verify'] = True
        return standardize_node(node)
    except:
        return None


def parse_ss_link(link):
    try:
        # 剔除不支持的复杂 plugin 参数，避免解析错误
        parts = urlparse(link)
        if parts.query and 'plugin=' in parts.query:
            return None
        if '@' in parts.netloc:
            user_info, host_info = parts.netloc.split('@', 1)
            server, port = host_info.rsplit(':', 1)
            decoded_user = decode_base64_content(user_info)
            user_info_str = decoded_user if (decoded_user and ':' in decoded_user) else unquote(user_info)
            if ':' not in user_info_str:
                return None
            method, password = user_info_str.split(':', 1)
        else:
            decoded = decode_base64_content(parts.netloc)
            if not decoded or '@' not in decoded:
                return None
            user_info, host_info = decoded.rsplit('@', 1)
            server, port = host_info.rsplit(':', 1)
            method, password = user_info.split(':', 1)
        node = {
            'name': unquote(parts.fragment).strip() if parts.fragment else f"ss_{server}",
            'type': 'ss',
            'server': server,
            'port': int(port),
            'cipher': method.strip().lower(),
            'password': password.strip()
        }
        return standardize_node(node)
    except:
        return None


def parse_ssr_link(link):
    try:
        decoded = decode_base64_content(link[6:])
        if not decoded:
            return None
        main = decoded.split('/')[0].split(':')
        if len(main) < 6:
            return None
        server, port, protocol, method, obfs, password_b64 = main[:6]
        # 仅保留兼容无混淆或 plain 协议的 SSR 转化为 SS
        if protocol not in ('origin', '') or obfs not in ('plain', ''):
            return None
        password = decode_base64_content(password_b64.split('?')[0])
        if not password:
            return None
        return standardize_node({
            'name': f"ssr_{server}",
            'type': 'ss',
            'server': server,
            'port': int(port),
            'cipher': method.lower().strip(),
            'password': password
        })
    except:
        return None


def parse_hysteria2_link(link):
    try:
        raw = link[12:] if link.startswith('hysteria2://') else link[6:]
        parts = urlparse(f"hysteria2://{raw}")
        if '@' not in parts.netloc:
            return None
        password, host_info = parts.netloc.split('@', 1)
        if host_info.startswith('['):
            i = host_info.index(']')
            server, port = host_info[1:i], host_info[i+2:]
        else:
            server, port = host_info.rsplit(':', 1)
        # 处理端口跳跃格式 (如 443,10000-20000)
        port = port.split(',')[0].split('-')[0]
        params = {k: v[0] for k, v in parse_qs(parts.query).items() if v}
        node = {
            'name': unquote(parts.fragment).strip() if parts.fragment else f"hy2_{server}",
            'type': 'hysteria2',
            'server': server,
            'port': int(port),
            'password': unquote(password)
        }
        if params.get('sni'):
            node['sni'] = params['sni']
        if params.get('alpn'):
            node['alpn'] = [a.strip() for a in unquote(params['alpn']).split(',') if a.strip()]
        if params.get('insecure') in ('1', 'true'):
            node['skip-cert-verify'] = True
        if params.get('obfs'):
            node['obfs'] = params['obfs']
            if params.get('obfs-password'):
                node['obfs-password'] = params['obfs-password']
        return standardize_node(node)
    except:
        return None


def parse_tuic_link(link):
    try:
        parts = urlparse(link)
        if '@' not in parts.netloc:
            return None
        user_info, host_info = parts.netloc.split('@', 1)
        uuid, password = user_info.split(':', 1) if ':' in user_info else (user_info, '')
        server, port = host_info.rsplit(':', 1)
        params = {k: v[0] for k, v in parse_qs(parts.query).items() if v}
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
            node['alpn'] = [a.strip() for a in unquote(params['alpn']).split(',') if a.strip()]
        if params.get('allow_insecure') in ('1', 'true') or params.get('insecure') in ('1', 'true'):
            node['skip-cert-verify'] = True
        return standardize_node(node)
    except:
        return None


def parse_anytls_link(link):
    try:
        parts = urlparse(link)
        if '@' not in parts.netloc:
            return None
        password, host_info = parts.netloc.split('@', 1)
        server, port = host_info.rsplit(':', 1)
        params = {k: v[0] for k, v in parse_qs(parts.query).items() if v}
        node = {
            'name': unquote(parts.fragment).strip() if parts.fragment else f"anytls_{server}",
            'type': 'anytls',
            'server': server,
            'port': int(port),
            'password': unquote(password)
        }
        if params.get('sni'):
            node['sni'] = params['sni']
        if params.get('insecure') in ('1', 'true'):
            node['skip-cert-verify'] = True
        return standardize_node(node)
    except:
        return None


# ==================== 节点完整转 URI 格式 (修复参数丢失 Bug) ====================
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
    except:
        pass
    return None


def _vmess_uri(n):
    net = n.get('network', 'tcp')
    path, host = '', ''
    if net == 'ws' and isinstance(n.get('ws-opts'), dict):
        path = n['ws-opts'].get('path', '/')
        host = n['ws-opts'].get('headers', {}).get('Host', '')
    elif net == 'grpc' and isinstance(n.get('grpc-opts'), dict):
        path = n['grpc-opts'].get('grpc-service-name', '')
    elif net == 'h2' and isinstance(n.get('h2-opts'), dict):
        path = n['h2-opts'].get('path', '/')
        hosts = n['h2-opts'].get('host', [])
        host = ','.join(hosts) if isinstance(hosts, list) else str(hosts)
    elif net == 'httpupgrade' and isinstance(n.get('httpupgrade-opts'), dict):
        path = n['httpupgrade-opts'].get('path', '/')
        host = n['httpupgrade-opts'].get('host', '')

    data = {
        'v': '2',
        'ps': n.get('name', ''),
        'add': n.get('server', ''),
        'port': str(n.get('port', '')),
        'id': n.get('uuid', ''),
        'aid': str(n.get('alterId', 0)),
        'scy': n.get('cipher', 'auto'),
        'net': net,
        'type': 'none',
        'host': host,
        'path': path,
        'tls': 'tls' if n.get('tls') else '',
        'sni': n.get('servername', ''),
        'fp': n.get('client-fingerprint', '')
    }
    if n.get('alpn') and isinstance(n['alpn'], list):
        data['alpn'] = ','.join(n['alpn'])
    raw = json.dumps(data, ensure_ascii=False)
    return f"vmess://{base64.b64encode(raw.encode('utf-8')).decode('utf-8')}"


def _vless_uri(n):
    net = n.get('network', 'tcp')
    p = {'type': net, 'encryption': 'none'}
    if n.get('tls'):
        if n.get('reality-opts'):
            p['security'] = 'reality'
            ro = n['reality-opts']
            if ro.get('public-key'):
                p['pbk'] = ro['public-key']
            if ro.get('short-id'):
                p['sid'] = ro['short-id']
        else:
            p['security'] = 'tls'
            if n.get('skip-cert-verify'):
                p['allowInsecure'] = '1'
    if n.get('servername'):
        p['sni'] = n['servername']
    if n.get('client-fingerprint'):
        p['fp'] = n['client-fingerprint']
    if n.get('flow'):
        p['flow'] = n['flow']
    if n.get('alpn') and isinstance(n['alpn'], list):
        p['alpn'] = ','.join(n['alpn'])

    if net == 'ws' and isinstance(n.get('ws-opts'), dict):
        p['path'] = n['ws-opts'].get('path', '/')
        host = n['ws-opts'].get('headers', {}).get('Host', '')
        if host:
            p['host'] = host
    elif net == 'grpc' and isinstance(n.get('grpc-opts'), dict):
        sn = n['grpc-opts'].get('grpc-service-name', '')
        if sn:
            p['serviceName'] = sn
    elif net == 'httpupgrade' and isinstance(n.get('httpupgrade-opts'), dict):
        p['path'] = n['httpupgrade-opts'].get('path', '/')
        if n['httpupgrade-opts'].get('host'):
            p['host'] = n['httpupgrade-opts']['host']

    q = '&'.join(f"{k}={quote(str(v))}" for k, v in p.items() if v is not None and v != '')
    return f"vless://{n['uuid']}@{n['server']}:{n['port']}?{q}#{quote(n.get('name', ''))}"


def _trojan_uri(n):
    net = n.get('network', 'tcp')
    p = {'type': net, 'sni': n.get('sni', n['server'])}
    if n.get('skip-cert-verify'):
        p['allowInsecure'] = '1'
    if n.get('client-fingerprint'):
        p['fp'] = n['client-fingerprint']
    if n.get('alpn') and isinstance(n['alpn'], list):
        p['alpn'] = ','.join(n['alpn'])
    if net == 'ws' and isinstance(n.get('ws-opts'), dict):
        p['path'] = n['ws-opts'].get('path', '/')
        host = n['ws-opts'].get('headers', {}).get('Host', '')
        if host:
            p['host'] = host
    elif net == 'grpc' and isinstance(n.get('grpc-opts'), dict):
        sn = n['grpc-opts'].get('grpc-service-name', '')
        if sn:
            p['serviceName'] = sn
    q = '&'.join(f"{k}={quote(str(v))}" for k, v in p.items() if v is not None and v != '')
    return f"trojan://{quote(str(n['password']))}@{n['server']}:{n['port']}?{q}#{quote(n.get('name', ''))}"


def _ss_uri(n):
    ui = base64.urlsafe_b64encode(f"{n['cipher']}:{n['password']}".encode('utf-8')).decode('utf-8').rstrip('=')
    return f"ss://{ui}@{n['server']}:{n['port']}#{quote(n.get('name', ''))}"


def _hysteria2_uri(n):
    p = {}
    if n.get('sni'):
        p['sni'] = n['sni']
    if n.get('skip-cert-verify'):
        p['insecure'] = '1'
    if n.get('obfs'):
        p['obfs'] = n['obfs']
        if n.get('obfs-password'):
            p['obfs-password'] = n['obfs-password']
    if n.get('alpn') and isinstance(n['alpn'], list):
        p['alpn'] = ','.join(n['alpn'])
    q = '&'.join(f"{k}={quote(str(v))}" for k, v in p.items() if v is not None and v != '')
    return f"hysteria2://{quote(str(n['password']))}@{n['server']}:{n['port']}?{q}#{quote(n.get('name', ''))}"


def _tuic_uri(n):
    p = {
        'congestion_control': n.get('congestion-controller', 'bbr'),
        'udp_relay_mode': n.get('udp-relay-mode', 'native')
    }
    if n.get('sni'):
        p['sni'] = n['sni']
    if n.get('skip-cert-verify'):
        p['allow_insecure'] = '1'
    if n.get('alpn') and isinstance(n['alpn'], list):
        p['alpn'] = ','.join(n['alpn'])
    q = '&'.join(f"{k}={quote(str(v))}" for k, v in p.items() if v is not None and v != '')
    return f"tuic://{quote(str(n['uuid']))}:{quote(str(n['password']))}@{n['server']}:{n['port']}?{q}#{quote(n.get('name', ''))}"


def _anytls_uri(n):
    p = {}
    if n.get('sni'):
        p['sni'] = n['sni']
    if n.get('skip-cert-verify'):
        p['insecure'] = '1'
    q = '&'.join(f"{k}={quote(str(v))}" for k, v in p.items() if v is not None and v != '')
    return f"anytls://{quote(str(n['password']))}@{n['server']}:{n['port']}?{q}#{quote(n.get('name', ''))}"


# ==================== 解析主入口 ====================
def parse_all_nodes(all_contents):
    all_nodes, unique_set = [], set()
    for url, content in all_contents.items():
        nodes = []
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict) and isinstance(data.get('proxies'), list):
                for proxy in data['proxies']:
                    if isinstance(proxy, dict) and all(k in proxy for k in ['name', 'server', 'port', 'type']):
                        node = standardize_node(dict(proxy))
                        if node:
                            h = node_hash(node)
                            if h not in unique_set:
                                nodes.append(node)
                                unique_set.add(h)
        except:
            pass

        if not nodes:
            decoded = decode_base64_content(content) or content
            for line in decoded.splitlines():
                node = parse_node(line.strip())
                if node:
                    h = node_hash(node)
                    if h not in unique_set:
                        nodes.append(node)
                        unique_set.add(h)

        all_nodes.extend(nodes)
        if nodes:
            logger.info(f"  └─ 解析到 {len(nodes)} 个有效节点 ({url[:50]}...)")
    logger.info(f"订阅抓取合并完成: 共提取到 {len(all_nodes)} 个标准化节点")
    return all_nodes


# ==================== 核心进程管理与防泄漏配置生成 ====================
def _kill_process(process):
    if process:
        try:
            process.terminate()
            process.wait(timeout=1.5)
        except:
            try:
                process.kill()
            except:
                pass


def _wait_for_clash_api(api_addr, timeout=8):
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = safe_request_get(f'http://{api_addr}/version', timeout=1)
            if r.status_code == 200:
                return True
        except:
            pass
        time.sleep(0.15)
    return False


def _build_clash_test_config(proxies_list, api_port, socks_port):
    """
    构建绝对防泄漏的 Clash/Mihomo 测试配置：
    强制将所有流量通过 rules: ['MATCH,TEST_GROUP'] 路由至代理节点，严禁走 DIRECT！
    """
    proxy_names = [p['name'] for p in proxies_list]
    return {
        'socks-port': socks_port,
        'external-controller': f'127.0.0.1:{api_port}',
        'mode': 'rule',
        'log-level': 'silent',
        'allow-lan': False,
        'ipv6': False,
        'proxies': proxies_list,
        'proxy-groups': [
            {
                'name': 'TEST_GROUP',
                'type': 'select',
                'proxies': proxy_names
            }
        ],
        'rules': [
            'MATCH,TEST_GROUP'
        ]
    }


# ==================== 阶段 1: Mihomo 全协议批量并发初筛 ====================
def _query_clash_node_delay(api_addr, node_name, timeout_ms):
    url = f"http://{api_addr}/proxies/{quote(node_name, safe='')}/delay"
    params_url = f"{url}?url={quote(GSTATIC_204_URL)}&timeout={timeout_ms}"
    try:
        r = safe_request_get(params_url, timeout=(timeout_ms / 1000.0) + 1.5)
        if r.status_code == 200:
            data = r.json()
            delay = data.get('delay', -1)
            if isinstance(delay, (int, float)) and delay > 0:
                return int(delay)
    except:
        pass
    return -1


def _test_stage1_batch_with_clash(batch_nodes):
    """
    在单个 Mihomo 进程中挂载一批节点，利用其内部异步引擎通过 REST API 并发测速
    支持全部协议 (VMess/VLESS/Reality/Hy2/TUIC/Trojan/SS/WS/gRPC)
    """
    rand_id = random_string()
    config_path = f'/tmp/clash_s1_{rand_id}.yaml'
    api_port, socks_port = get_free_port(), get_free_port()
    api_addr = f'127.0.0.1:{api_port}'

    # 为批次内节点赋予临时唯一 ID，防止重名冲突
    indexed_nodes = []
    name_map = {}
    for idx, n in enumerate(batch_nodes):
        temp_name = f"s1_node_{idx}_{rand_id}"
        c_node = dict(n)
        c_node['name'] = temp_name
        indexed_nodes.append(c_node)
        name_map[temp_name] = n

    cfg = _build_clash_test_config(indexed_nodes, api_port, socks_port)
    process = None
    passed_results = []

    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(cfg, f, allow_unicode=True, sort_keys=False)

        process = subprocess.Popen(
            [CLASH_BINARY_PATH, '-f', config_path, '-d', '/tmp'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        if not _wait_for_clash_api(api_addr, timeout=6):
            # 若批次中存在个别畸形节点导致 Clash 启动失败，自动折半递归隔离问题节点
            _kill_process(process)
            if len(batch_nodes) > 4:
                mid = len(batch_nodes) // 2
                return _test_stage1_batch_with_clash(batch_nodes[:mid]) + _test_stage1_batch_with_clash(batch_nodes[mid:])
            return []

        timeout_ms = int(V2RAY_TEST_TIMEOUT * 1000)
        with ThreadPoolExecutor(max_workers=min(STAGE1_API_CONCURRENCY, len(indexed_nodes))) as ex:
            future_map = {
                ex.submit(_query_clash_node_delay, api_addr, temp_name, timeout_ms): temp_name
                for temp_name in name_map.keys()
            }
            for fut in as_completed(future_map):
                t_name = future_map[fut]
                try:
                    delay = fut.result()
                    if delay > 0:
                        passed_results.append({'node': name_map[t_name], 'delay': delay})
                except:
                    pass
    except:
        pass
    finally:
        _kill_process(process)
        try:
            os.remove(config_path)
        except:
            pass

    return passed_results


def stage1_v2ray_test(nodes):
    logger.info(f"\n{'='*60}")
    logger.info(f"[阶段1/3] Mihomo 全协议高并发握手初筛 ({len(nodes)} 个候选节点)")
    logger.info(f"{'='*60}")

    batches = [nodes[i:i + STAGE1_BATCH_SIZE] for i in range(0, len(nodes), STAGE1_BATCH_SIZE)]
    results = []

    with tqdm(total=len(nodes), desc="全协议初筛") as pbar:
        for batch in batches:
            batch_res = _test_stage1_batch_with_clash(batch)
            results.extend(batch_res)
            pbar.update(len(batch))

    results.sort(key=lambda x: x['delay'])
    top = results[:STAGE1_TOP_N]
    logger.info(f"✓ 阶段1完成: {len(results)}/{len(nodes)} 节点响应正常，优选前 {len(top)} 个进入真连接深测")
    return [x['node'] for x in top]


# ==================== 阶段 1.5 & 1.7: 真连接内容与出口 IP 严苛校验 ====================
def _verify_real_proxy_connectivity(socks_port, pass_num=1):
    """
    通过 SOCKS5 代理端口执行严格防假活测试：
    第 1 轮 (内容与出口检验):
      1) 请求 Cloudflare Trace: 必须返回 200，校验出口 IP != 本机公网 IP (防直连泄漏)，且出口国家 != CN (防境内回国死节点)
      2) 请求 Google robots.txt: 必须返回 200，且响应正文包含 'User-agent:' 和 'Disallow:' (防假 204 劫持与 0 带宽断流)
    第 2 轮 (双源稳定性复核):
      1) 校验 Google generate_204 (严格状态码 204 且无重定向)
      2) 校验 Gstatic generate_204 (严格状态码 204 且无重定向)
    """
    proxies = {
        'http': f'socks5h://127.0.0.1:{socks_port}',
        'https': f'socks5h://127.0.0.1:{socks_port}'
    }

    try:
        start_time = time.time()
        if pass_num == 1:
            # 1. Cloudflare Trace 出口真实性检验
            r_trace = safe_request_get(TRACE_TEST_URL, proxies=proxies, timeout=REAL_TEST_TIMEOUT, allow_redirects=False)
            if r_trace.status_code != 200 or 'ip=' not in r_trace.text or 'loc=' not in r_trace.text:
                return -1

            trace_data = {}
            for line in r_trace.text.splitlines():
                if '=' in line:
                    k, v = line.split('=', 1)
                    trace_data[k.strip()] = v.strip()

            exit_ip = trace_data.get('ip', '')
            exit_loc = trace_data.get('loc', '').upper()

            # 严防直连穿透泄漏
            if LOCAL_PUBLIC_IP and exit_ip == LOCAL_PUBLIC_IP:
                return -1
            # 剔除出口在中国大陆境内的非翻墙节点
            if exit_loc in ('CN', ''):
                return -1

            # 2. Google 真实载荷内容下载检验 (消灭假 204 与 0 带宽节点)
            r_robots = safe_request_get(GOOGLE_ROBOTS_URL, proxies=proxies, timeout=REAL_TEST_TIMEOUT, allow_redirects=False)
            if r_robots.status_code != 200:
                return -1
            body = r_robots.text
            if 'User-agent:' not in body or 'Disallow:' not in body or len(body) < 200:
                return -1

            return round((time.time() - start_time) * 1000)

        else:
            # 第 2 轮：双端 204 稳定性与抗丢包复测
            r1 = safe_request_get(GOOGLE_204_URL, proxies=proxies, timeout=REAL_TEST_TIMEOUT, allow_redirects=False)
            if r1.status_code != 204:
                return -1
            r2 = safe_request_get(GSTATIC_204_URL, proxies=proxies, timeout=REAL_TEST_TIMEOUT, allow_redirects=False)
            if r2.status_code != 204:
                return -1
            return round((time.time() - start_time) * 1000)
    except:
        return -1


def _worker_real_test_chunk(chunk_nodes, pass_num):
    """
    工作线程：启动独立 Clash 实例并通过 API 切换节点，依次对 chunk 内节点进行真连接 SOCKS5 校验
    """
    rand_id = random_string()
    config_path = f'/tmp/clash_real_{rand_id}.yaml'
    api_port, socks_port = get_free_port(), get_free_port()
    api_addr = f'127.0.0.1:{api_port}'

    indexed_nodes = []
    name_map = {}
    for idx, n in enumerate(chunk_nodes):
        t_name = f"real_{idx}_{rand_id}"
        c_node = dict(n)
        c_node['name'] = t_name
        indexed_nodes.append(c_node)
        name_map[t_name] = n

    cfg = _build_clash_test_config(indexed_nodes, api_port, socks_port)
    process = None
    passed = []

    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(cfg, f, allow_unicode=True, sort_keys=False)

        process = subprocess.Popen(
            [CLASH_BINARY_PATH, '-f', config_path, '-d', '/tmp'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        if not _wait_for_clash_api(api_addr, timeout=6):
            return []

        switch_url = f'http://{api_addr}/proxies/TEST_GROUP'
        for t_name, orig_node in name_map.items():
            try:
                # 切换当前测试节点
                put_resp = safe_request_put(switch_url, json_data={'name': t_name}, timeout=2)
                if put_resp.status_code not in (200, 204):
                    continue
                delay = _verify_real_proxy_connectivity(socks_port, pass_num=pass_num)
                if delay > 0:
                    passed.append({'node': orig_node, 'delay': delay})
            except:
                pass
    except:
        pass
    finally:
        _kill_process(process)
        try:
            os.remove(config_path)
        except:
            pass

    return passed


def stage_real_google_test(nodes, pass_num=1):
    label = "阶段1.7/3" if pass_num == 2 else "阶段1.5/3"
    desc_detail = "Google双源204稳定性复核" if pass_num == 2 else "CF出口IP检验 + Google真实正文下载"
    logger.info(f"\n{'='*60}")
    logger.info(f"[{label}] 真连接严苛测试 第{pass_num}轮 ({len(nodes)} 个节点)")
    logger.info(f"  校验项目: {desc_detail} (强制代理路由，严禁直连与重定向)")
    logger.info(f"{'='*60}")

    chunks = [nodes[i:i + REAL_WORKER_BATCH_SIZE] for i in range(0, len(nodes), REAL_WORKER_BATCH_SIZE)]
    results = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_REAL) as ex:
        futures = {ex.submit(_worker_real_test_chunk, chunk, pass_num): len(chunk) for chunk in chunks}
        with tqdm(total=len(nodes), desc=f"真连接校验[第{pass_num}轮]") as pbar:
            for future in as_completed(futures):
                chunk_len = futures[future]
                try:
                    chunk_res = future.result(timeout=REAL_WORKER_BATCH_SIZE * (REAL_TEST_TIMEOUT * 2 + 3))
                    if chunk_res:
                        results.extend(chunk_res)
                except:
                    pass
                pbar.update(chunk_len)

    results.sort(key=lambda x: x['delay'])
    passed = [x['node'] for x in results]
    logger.info(f"✓ 第{pass_num}轮完成: {len(passed)}/{len(nodes)} 个节点真实可用")
    return passed


# ==================== 阶段 2: Scholar 学术验证 ====================
def verify_scholar_access(socks_port, node_name):
    if not STAGE2_SCHOLAR_TEST:
        return True
    try:
        proxies = {
            'http': f'socks5h://127.0.0.1:{socks_port}',
            'https': f'socks5h://127.0.0.1:{socks_port}'
        }
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9'
        }
        r = safe_request_get(
            SCHOLAR_VERIFY_URL, proxies=proxies, timeout=10,
            allow_redirects=True, headers=headers
        )
        if r.status_code == 200:
            cl = r.text.lower()
            blocked = any(kw in cl for kw in ['captcha', 'automated queries', '/sorry/index', 'unusual traffic', 'recaptcha'])
            has_scholar_content = ('gs_r' in cl or 'scholar' in cl) and len(cl) > 2000
            if not blocked and has_scholar_content:
                logger.info(f"✓ Scholar免验证通过: {node_name}")
                return True
    except:
        pass
    return False


def _worker_scholar_test_chunk(chunk_nodes):
    rand_id = random_string()
    config_path = f'/tmp/clash_sch_{rand_id}.yaml'
    api_port, socks_port = get_free_port(), get_free_port()
    api_addr = f'127.0.0.1:{api_port}'

    indexed_nodes = []
    name_map = {}
    for idx, n in enumerate(chunk_nodes):
        t_name = f"sch_{idx}_{rand_id}"
        c_node = dict(n)
        c_node['name'] = t_name
        indexed_nodes.append(c_node)
        name_map[t_name] = n

    cfg = _build_clash_test_config(indexed_nodes, api_port, socks_port)
    process = None
    passed = []

    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(cfg, f, allow_unicode=True, sort_keys=False)

        process = subprocess.Popen(
            [CLASH_BINARY_PATH, '-f', config_path, '-d', '/tmp'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        if not _wait_for_clash_api(api_addr, timeout=6):
            return []

        switch_url = f'http://{api_addr}/proxies/TEST_GROUP'
        for t_name, orig_node in name_map.items():
            try:
                put_resp = safe_request_put(switch_url, json_data={'name': t_name}, timeout=2)
                if put_resp.status_code not in (200, 204):
                    continue
                if verify_scholar_access(socks_port, orig_node['name']):
                    passed.append(orig_node)
            except:
                pass
    except:
        pass
    finally:
        _kill_process(process)
        try:
            os.remove(config_path)
        except:
            pass

    return passed


def stage2_clash_scholar_test(nodes):
    logger.info(f"\n{'='*60}")
    logger.info(f"[阶段2/3] Google Scholar 学术访问验证 ({len(nodes)} 个节点)")
    logger.info(f"{'='*60}")

    chunks = [nodes[i:i + 10] for i in range(0, len(nodes), 10)]
    passed = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_CLASH) as ex:
        futures = {ex.submit(_worker_scholar_test_chunk, chunk): len(chunk) for chunk in chunks}
        with tqdm(total=len(nodes), desc="Scholar验证") as pbar:
            for future in as_completed(futures):
                chunk_len = futures[future]
                try:
                    res = future.result(timeout=150)
                    if res:
                        passed.extend(res)
                except:
                    pass
                pbar.update(chunk_len)

    passed = passed[:MAX_NODES_LIMIT]
    logger.info(f"✓ 阶段2完成: {len(passed)} 个节点通过学术验证")
    return passed


# ==================== 输出文件生成 ====================
def ensure_unique_names(nodes):
    counts, result = {}, []
    for node in nodes:
        name = node['name']
        if name in counts:
            counts[name] += 1
            node = dict(node)
            node['name'] = f"{name}_{counts[name]}"
        else:
            counts[name] = 1
        result.append(node)
    return result


def generate_clash_config(nodes, output_file):
    logger.info(f"生成 Clash 配置: {len(nodes)} 节点 → {output_file}")
    config = {
        'port': 7890,
        'socks-port': 7891,
        'mixed-port': 7892,
        'allow-lan': False,
        'mode': 'rule',
        'log-level': 'info',
        'unified-delay': True,
        'tcp-concurrent': True,
        'dns': {
            'enable': True,
            'enhanced-mode': 'fake-ip',
            'fake-ip-range': '198.18.0.1/16',
            'nameserver': ['https://doh.pub/dns-query', '223.5.5.5'],
            'fallback': ['https://1.1.1.1/dns-query', 'https://dns.google/dns-query'],
            'fallback-filter': {'geoip': True, 'geoip-code': 'CN'}
        },
        'proxies': nodes
    }
    if nodes:
        names = [n['name'] for n in nodes]
        config['proxy-groups'] = [
            {
                'name': 'PROXY',
                'type': 'select',
                'proxies': ['AUTO', 'FALLBACK'] + names + ['DIRECT']
            },
            {
                'name': 'AUTO',
                'type': 'url-test',
                'proxies': names,
                'url': 'https://www.gstatic.com/generate_204',
                'interval': 120,
                'tolerance': 50,
                'timeout': 2000,
                'lazy': False
            },
            {
                'name': 'FALLBACK',
                'type': 'fallback',
                'proxies': names,
                'url': 'https://www.gstatic.com/generate_204',
                'interval': 120,
                'timeout': 2000,
                'lazy': False
            }
        ]
    else:
        config['proxy-groups'] = [{'name': 'PROXY', 'type': 'select', 'proxies': ['DIRECT']}]

    config['rules'] = [
        'DOMAIN-SUFFIX,scholar.google.com,PROXY',
        'DOMAIN-SUFFIX,google.com,PROXY',
        'DOMAIN-SUFFIX,googleapis.com,PROXY',
        'DOMAIN-SUFFIX,gstatic.com,PROXY',
        'DOMAIN-SUFFIX,github.com,PROXY',
        'DOMAIN-SUFFIX,openai.com,PROXY',
        'DOMAIN-SUFFIX,claude.ai,PROXY',
        'GEOIP,CN,DIRECT',
        'MATCH,PROXY'
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
    global LOCAL_PUBLIC_IP
    logger.info("正在检测本机公网 IP 与网络环境...")
    try:
        r = safe_request_get(TRACE_TEST_URL, timeout=5, allow_redirects=False)
        if r.status_code == 200 and 'ip=' in r.text:
            for line in r.text.splitlines():
                if line.startswith('ip='):
                    LOCAL_PUBLIC_IP = line.split('=', 1)[1].strip()
                    break
    except:
        pass

    if not LOCAL_PUBLIC_IP:
        try:
            r = safe_request_get('https://api.ipify.org', timeout=4, allow_redirects=False)
            if r.status_code == 200:
                LOCAL_PUBLIC_IP = r.text.strip()
        except:
            pass

    if LOCAL_PUBLIC_IP:
        logger.info(f"✓ 已记录本机公网 IP: {LOCAL_PUBLIC_IP} (测速时将强制比对出口 IP，严防直连穿透)")

    try:
        r = safe_request_get(GOOGLE_204_URL, timeout=3, allow_redirects=False)
        if r.status_code == 204:
            logger.warning("提示：当前运行环境在海外 (如 GitHub Actions)，已开启防直连泄漏与真實载荷验证。")
    except:
        logger.info("✓ 当前运行环境在中国大陆境内，具备天然 GFW 阻断过滤优势。")


# ==================== 主流程 ====================
def main():
    logger.info("=" * 60)
    logger.info("Clash/V2Ray 节点深度清洗聚合测速工具 v3.0")
    logger.info("流程: 深度清洗 → Mihomo全协议初筛 → 出口IP+Google正文双轮深测 → Scholar验证")
    logger.info("=" * 60)

    check_environment()

    if not os.path.exists(CLASH_BINARY_PATH):
        logger.error(f"未找到 Clash/Mihomo 二进制文件: {CLASH_BINARY_PATH}")
        sys.exit(1)

    # 确保二进制文件具有可执行权限
    try:
        os.chmod(CLASH_BINARY_PATH, 0o755)
    except:
        pass

    if not os.path.exists(SUBSCRIPTION_URLS_FILE):
        with open(SUBSCRIPTION_URLS_FILE, 'w', encoding='utf-8') as f:
            f.write("# 在此处填入订阅URL，每行一个\n")
        logger.error(f"请在 {SUBSCRIPTION_URLS_FILE} 中填入订阅链接后重试")
        return

    with open(SUBSCRIPTION_URLS_FILE, 'r', encoding='utf-8') as f:
        urls = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    if not urls:
        logger.warning("订阅列表为空")
        return

    logger.info(f"读取到 {len(urls)} 个订阅源，正在并发抓取...")
    contents = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_FETCH) as ex:
        futures = {ex.submit(get_subscription_content, url): url for url in urls}
        for f in tqdm(as_completed(futures), total=len(futures), desc="抓取订阅"):
            url = futures[f]
            content = f.result()
            if content:
                contents[url] = content

    if not contents:
        logger.error("所有订阅均抓取失败，退出程序")
        return

    all_nodes = parse_all_nodes(contents)
    if not all_nodes:
        logger.warning("未解析到任何有效节点，退出程序")
        return

    # ── 前置清洗与去重 ──
    clean_nodes = clean_and_deduplicate_nodes(all_nodes, max_limit=MAX_PRE_TEST_NODES)
    if not clean_nodes:
        logger.warning("清洗后无可测试节点")
        return

    # ── 阶段1: Mihomo 全协议并发延迟初筛 ──
    if STAGE1_V2RAY_TEST:
        stage1_nodes = stage1_v2ray_test(clean_nodes)
    else:
        stage1_nodes = clean_nodes[:STAGE1_TOP_N]

    if not stage1_nodes:
        logger.warning("阶段1后无存活节点")
        return

    # ── 阶段1.5: 真连接第1轮 (Cloudflare 出口IP校验 + Google robots.txt 正文下载) ──
    real1_nodes = stage_real_google_test(stage1_nodes, pass_num=1) if STAGE15_REAL_TEST else stage1_nodes
    if not real1_nodes:
        logger.warning("真连接第1轮无节点通过")
        return

    # ── 阶段1.7: 真连接第2轮 (Google + Gstatic 双源 204 稳定性复核) ──
    real2_nodes = stage_real_google_test(real1_nodes, pass_num=2) if STAGE15_REAL_TEST else real1_nodes
    if not real2_nodes:
        logger.warning("真连接第2轮无节点通过")
        return

    real2_nodes = ensure_unique_names(real2_nodes[:MAX_NODES_LIMIT])

    # 输出基础可用配置文件 (Clash + V2Ray Base64)
    generate_clash_config(real2_nodes, OUTPUT_CLASH_FILE)
    generate_v2ray_base64_subscription(real2_nodes, OUTPUT_V2RAY_BASE64_FILE)

    with open(UPDATE_TIME_FILE, 'w', encoding='utf-8') as f:
        f.write(f"更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"原始抓取节点数: {len(all_nodes)}\n")
        f.write(f"清洗去重后送测: {len(clean_nodes)}\n")
        f.write(f"全协议初筛通过: {len(stage1_nodes)}\n")
        f.write(f"真连接严苛两轮通过: {len(real2_nodes)}\n")

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
            logger.info(f"\n全部流程完成！Scholar纯净节点数量: {len(final_nodes)}")
            logger.info(f"  Clash配置: {OUTPUT_CLASH_FILE_SCHOLAR}")
            logger.info(f"  V2Ray Base64: {scholar_b64}")
        else:
            logger.warning("未检测到可通过 Google Scholar 验证的纯净节点")
            generate_clash_config([], OUTPUT_CLASH_FILE_SCHOLAR)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\n用户主动中断运行")
        sys.exit(0)
    except Exception as e:
        logger.error(f"致命错误: {e}", exc_info=True)
        sys.exit(1)
