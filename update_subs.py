import base64
import json
import os
import requests
import socket
import time
import yaml
import binascii
from datetime import datetime
from urllib.parse import unquote, urlparse, parse_qs

# --- 配置 ---
# 订阅链接文件路径
SUBSCRIPTION_URLS_FILE = 'subscription_urls.txt'
# 输出的 Clash 订阅文件路径
OUTPUT_CLASH_FILE = 'clash_subscription.yaml'
# 输出的更新时间记录文件路径
UPDATE_TIME_FILE = 'update_time.txt'
# 延迟测试超时时间（秒）
LATENCY_TEST_TIMEOUT = 2
# 可接受的最大延迟（毫秒）
MAX_LATENCY_MS = 500

def get_subscription_content(url):
    """通过 URL 获取订阅内容。"""
    headers = {'User-Agent': 'Clash/1.11.0'}
    try:
        print(f"正在获取订阅: {url}")
        response = requests.get(url, timeout=15, headers=headers)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"获取订阅失败: {url}, 错误: {e}")
        return None

def decode_base64_content(content):
    """解码 Base64 编码的订阅内容。"""
    try:
        # 增加 padding 确保 base64 解码正确
        missing_padding = len(content) % 4
        if missing_padding:
            content += '=' * (4 - missing_padding)
        return base64.b64decode(content).decode('utf-8')
    except (binascii.Error, UnicodeDecodeError) as e:
        print(f"Base64 解码失败: {e}")
        return None

def parse_node(link):
    """
    解析单个节点链接，作为路由分发到具体的解析函数。
    """
    link = link.strip()
    if link.startswith('ss://'):
        return parse_ss_link(link)
    elif link.startswith('vmess://'):
        return parse_vmess_link(link)
    elif link.startswith('trojan://'):
        return parse_trojan_link(link)
    elif link.startswith('vless://'):
        return parse_vless_link(link)
    elif link.startswith('hysteria://'):
        return parse_hysteria_link(link)
    elif link.startswith('hysteria2://'):
        return parse_hysteria2_link(link)
    return None

def parse_ss_link(ss_link):
    """解析 Shadowsocks 链接。"""
    try:
        parts = urlparse(ss_link)
        user_info, host_info = parts.netloc.split('@')
        server, port = host_info.split(':')
        
        try:
            decoded_user_info = base64.b64decode(user_info).decode('utf-8')
            method, password = decoded_user_info.split(':', 1)
        except:
            user_info = unquote(user_info)
            method, password = user_info.split(':', 1)

        remarks = unquote(parts.fragment) if parts.fragment else f"ss_{server}"
        return {'name': remarks, 'type': 'ss', 'server': server, 'port': int(port), 
                'cipher': method, 'password': password, 'udp': True}
    except Exception as e:
        print(f"解析 SS 链接失败: {ss_link}, 错误: {e}")
        return None

def parse_vmess_link(vmess_link):
    """解析 Vmess 链接。"""
    try:
        decoded_link = base64.b64decode(vmess_link[8:]).decode('utf-8')
        vmess_data = json.loads(decoded_link)
        node = {'name': vmess_data.get('ps', vmess_data.get('add')), 'type': 'vmess', 
                'server': vmess_data.get('add'), 'port': int(vmess_data.get('port')), 
                'uuid': vmess_data.get('id'), 'alterId': int(vmess_data.get('aid')), 
                'cipher': vmess_data.get('scy', 'auto'), 'udp': True,
                'tls': vmess_data.get('tls') == 'tls', 'network': vmess_data.get('net')}
        if node['network'] == 'ws':
            ws_opts = {'path': vmess_data.get('path', '/')}
            if vmess_data.get('host'):
                ws_opts['headers'] = {'Host': vmess_data.get('host')}
            node['ws-opts'] = ws_opts
        return node
    except Exception as e:
        print(f"解析 Vmess 链接失败: {vmess_link}, 错误: {e}")
        return None

def parse_trojan_link(trojan_link):
    """解析 Trojan 链接。"""
    try:
        parts = urlparse(trojan_link)
        password, host_info = parts.netloc.split('@')
        server, port = host_info.split(':')
        remarks = unquote(parts.fragment) if parts.fragment else f"trojan_{server}"
        params = {k: v[0] for k, v in parse_qs(parts.query).items()}
        node = {'name': remarks, 'type': 'trojan', 'server': server, 'port': int(port),
                'password': password, 'udp': True, 'sni': params.get('sni', server),
                'skip-cert-verify': params.get('allowInsecure', 'false').lower() in ['true', '1']}
        return node
    except Exception as e:
        print(f"解析 Trojan 链接失败: {trojan_link}, 错误: {e}")
        return None

def parse_vless_link(vless_link):
    """解析 VLESS 链接。"""
    try:
        parts = urlparse(vless_link)
        uuid, host_info = parts.netloc.split('@')
        server, port = host_info.split(':')
        remarks = unquote(parts.fragment) if parts.fragment else f"vless_{server}"
        params = {k: v[0] for k, v in parse_qs(parts.query).items()}
        
        node = {'name': remarks, 'type': 'vless', 'server': server, 'port': int(port),
                'uuid': uuid, 'udp': True, 'tls': params.get('security') == 'tls',
                'network': params.get('type', 'tcp'), 
                'servername': params.get('sni', server),
                'flow': params.get('flow', '')}

        if node['network'] == 'ws':
            node['ws-opts'] = {'path': params.get('path', '/'), 'headers': {'Host': params.get('host', server)}}
        elif node['network'] == 'grpc':
            node['grpc-opts'] = {'grpc-service-name': params.get('serviceName', '')}
            
        return node
    except Exception as e:
        print(f"解析 VLESS 链接失败: {vless_link}, 错误: {e}")
        return None

def parse_hysteria_link(hy_link):
    """解析 Hysteria (v1) 链接。"""
    try:
        parts = urlparse(hy_link)
        server, port = parts.netloc.split(':')
        remarks = unquote(parts.fragment) if parts.fragment else f"hysteria_{server}"
        params = {k: v[0] for k, v in parse_qs(parts.query).items()}
        
        return {'name': remarks, 'type': 'hysteria', 'server': server, 'port': int(port),
                'protocol': params.get('protocol', 'udp'), 'auth_str': params.get('auth'),
                'up': int(params.get('upmbps', 50)), 'down': int(params.get('downmbps', 100)),
                'sni': params.get('peer', server),
                'skip-cert-verify': params.get('insecure', '0') == '1'}
    except Exception as e:
        print(f"解析 Hysteria 链接失败: {hy_link}, 错误: {e}")
        return None

def parse_hysteria2_link(hy2_link):
    """解析 Hysteria2 链接。"""
    try:
        parts = urlparse(hy2_link)
        password, host_info = parts.netloc.split('@')
        server, port = host_info.split(':')
        remarks = unquote(parts.fragment) if parts.fragment else f"hysteria2_{server}"
        params = {k: v[0] for k, v in parse_qs(parts.query).items()}
        
        return {'name': remarks, 'type': 'hysteria2', 'server': server, 'port': int(port),
                'password': password, 'sni': params.get('sni', server),
                'skip-cert-verify': params.get('insecure', '0') == '1'}
    except Exception as e:
        print(f"解析 Hysteria2 链接失败: {hy2_link}, 错误: {e}")
        return None

def test_node_latency(server, port):
    """测试节点的 TCP 延迟，返回毫秒或 -1 (失败)。"""
    try:
        addr = (server, int(port))
        start_time = time.time()
        with socket.create_connection(addr, timeout=LATENCY_TEST_TIMEOUT) as sock:
            end_time = time.time()
        latency = (end_time - start_time) * 1000
        return int(latency)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return -1

def main():
    """主函数"""
    if not os.path.exists(SUBSCRIPTION_URLS_FILE):
        print(f"错误: 订阅文件 '{SUBSCRIPTION_URLS_FILE}' 未找到。")
        return

    with open(SUBSCRIPTION_URLS_FILE, 'r', encoding='utf-8') as f:
        subscription_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    print(f"找到 {len(subscription_urls)} 个订阅链接。")
    
    all_nodes = []
    unique_nodes = set()

    for url in subscription_urls:
        content = get_subscription_content(url)
        if not content:
            continue
        
        # 尝试直接解析内容，如果失败再尝试 Base64 解码
        links_content = content
        if not any(proto in content for proto in ["ss://", "vmess://", "trojan://", "vless://", "hysteria://", "hysteria2://"]):
             links_content = decode_base64_content(content)
        
        if not links_content:
            continue
        
        links = links_content.splitlines()
        for link in links:
            node = parse_node(link)
            if node:
                node_id = (node['server'], node['port'], node['type'])
                if node_id not in unique_nodes:
                    all_nodes.append(node)
                    unique_nodes.add(node_id)
    
    print(f"去重后共解析出 {len(all_nodes)} 个节点。")

    fast_nodes = []
    print("\n--- 开始节点延迟测试 ---")
    for i, node in enumerate(all_nodes):
        latency = test_node_latency(node['server'], node['port'])
        # 使用 {:<40} 来保证对齐，适应更长的节点名
        print(f"({i+1}/{len(all_nodes)}) 测试节点: {node['name']:<40} ... ", end="")
        if 0 < latency < MAX_LATENCY_MS:
            print(f"延迟: {latency}ms [通过]")
            fast_nodes.append(node)
        else:
            print(f"延迟: {latency if latency > 0 else '超时或失败'} [丢弃]")
    print("--- 延迟测试结束 ---\n")
            
    print(f"筛选出 {len(fast_nodes)} 个可用节点。")

    if not fast_nodes:
        print("没有找到任何可用节点，已停止生成订阅文件。")
        # 即使没有节点，也更新时间戳文件，表示程序已运行
    
    # 始终写入文件，即使为空，以确保旧的订阅被覆盖
    clash_config = {'proxies': fast_nodes}
    try:
        with open(OUTPUT_CLASH_FILE, 'w', encoding='utf-8') as f:
            yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
        print(f"成功生成 Clash 订阅文件: {OUTPUT_CLASH_FILE}")
    except IOError as e:
        print(f"写入 Clash 配置文件失败: {e}")

    try:
        with open(UPDATE_TIME_FILE, 'w', encoding='utf-8') as f:
            update_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
            f.write(f"最后更新时间: {update_time}\n")
            f.write(f"可用节点数量: {len(fast_nodes)}\n")
        print(f"成功记录更新时间: {UPDATE_TIME_FILE}")
    except IOError as e:
        print(f"写入更新时间文件失败: {e}")

if __name__ == '__main__':
    main()
