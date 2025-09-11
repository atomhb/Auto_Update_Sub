import base64
import json
import os
import requests
import socket
import time
import yaml
import subprocess
from datetime import datetime
from urllib.parse import unquote, urlparse, parse_qs


SUBSCRIPTION_URLS_FILE = 'sub_urls.txt'
OUTPUT_CLASH_FILE = 'clash_subscription.yaml'
UPDATE_TIME_FILE = 'update_time.txt'
MAX_LATENCY_MS = 500

REAL_TEST_URL = 'http://cp.cloudflare.com/'

REAL_TEST_TIMEOUT = 50
XRAY_PATH = './xray'
XRAY_CONFIG_FILE = 'xray_config.json'
LOCAL_SOCKS_PORT = 10808

TCP_PING_TIMEOUT = 5

def get_subscription_content(url):
    headers = {'User-Agent': 'Clash/1.11.0'}
    try:
        print(f"正在获取订阅: {url}")
        response = requests.get(url, timeout=15, headers=headers)
        response.raise_for_status()
        response.encoding = 'utf-8'
        return response.text
    except requests.RequestException as e:
        print(f"获取订阅失败: {url}, 错误: {e}")
        return None

def decode_base64_content(content):
    try:
        if len(content) % 4 != 0:
            content += '=' * (4 - len(content) % 4)
        return base64.b64decode(content.encode('ascii')).decode('utf-8')
    except Exception as e:
        print(f"Base64 解码失败: {e}")
        return None

# --- 节点解析函数 (无改动) ---
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
        parts = urlparse(ss_link); user_info, host_info = parts.netloc.split('@'); server, port = host_info.split(':'); remarks = unquote(parts.fragment) if parts.fragment else f"ss_{server}";
        try: user_info_str = base64.b64decode(user_info).decode('utf-8')
        except: user_info_str = unquote(user_info)
        method, password = user_info_str.split(':', 1);
        return {'name': remarks, 'type': 'ss', 'server': server, 'port': int(port), 'cipher': method, 'password': password, 'udp': True}
    except: return None
def parse_vmess_link(vmess_link):
    try:
        b64_str = vmess_link[8:]; b64_str += '=' * (-len(b64_str) % 4); vmess_data = json.loads(base64.b64decode(b64_str).decode('utf-8'));
        node = {'name': vmess_data.get('ps', vmess_data.get('add')), 'type': 'vmess', 'server': vmess_data.get('add'), 'port': int(vmess_data.get('port')), 'uuid': vmess_data.get('id'), 'alterId': int(vmess_data.get('aid')), 'cipher': vmess_data.get('scy', 'auto'), 'udp': True, 'tls': vmess_data.get('tls') == 'tls', 'network': vmess_data.get('net')}
        if node['tls']: node['servername'] = vmess_data.get('sni', vmess_data.get('host', ''))
        if node['network'] == 'ws': node['ws-opts'] = {'path': vmess_data.get('path', '/'), 'headers': {'Host': vmess_data.get('host')} if vmess_data.get('host') else {}}
        return node
    except: return None
def parse_trojan_link(trojan_link):
    try:
        parts = urlparse(trojan_link); password, host_info = parts.netloc.split('@'); server, port = host_info.split(':'); remarks = unquote(parts.fragment) if parts.fragment else f"trojan_{server}"; params = {k: v[0] for k, v in parse_qs(parts.query).items()};
        return {'name': remarks, 'type': 'trojan', 'server': server, 'port': int(port), 'password': password, 'udp': True, 'sni': params.get('sni', server), 'skip-cert-verify': params.get('allowInsecure', 'false').lower() in ['true', '1']}
    except: return None
def parse_vless_link(vless_link):
    try:
        parts = urlparse(vless_link); uuid, host_info = parts.netloc.split('@'); server, port = host_info.split(':'); remarks = unquote(parts.fragment) if parts.fragment else f"vless_{server}"; params = {k: v[0] for k, v in parse_qs(parts.query).items()};
        node = {'name': remarks, 'type': 'vless', 'server': server, 'port': int(port), 'uuid': uuid, 'udp': True, 'tls': params.get('security') == 'tls', 'network': params.get('type', 'tcp'), 'servername': params.get('sni', server), 'flow': params.get('flow', '')}
        if node['network'] == 'ws': node['ws-opts'] = {'path': params.get('path', '/'), 'headers': {'Host': params.get('host', server)}}
        elif node['network'] == 'grpc': node['grpc-opts'] = {'grpc-service-name': params.get('serviceName', '')}
        return node
    except: return None
def parse_hysteria_link(hy_link):
    try:
        parts = urlparse(hy_link); server, port = parts.netloc.split(':'); remarks = unquote(parts.fragment) if parts.fragment else f"hysteria_{server}"; params = {k: v[0] for k, v in parse_qs(parts.query).items()};
        return {'name': remarks, 'type': 'hysteria', 'server': server, 'port': int(port), 'protocol': params.get('protocol', 'udp'), 'auth_str': params.get('auth'), 'up': int(params.get('upmbps', 50)), 'down': int(params.get('downmbps', 100)), 'sni': params.get('peer', server), 'skip-cert-verify': params.get('insecure', '0') == '1'}
    except: return None
def parse_hysteria2_link(hy2_link):
    try:
        parts = urlparse(hy2_link); password, host_info = parts.netloc.split('@'); server, port = host_info.split(':'); remarks = unquote(parts.fragment) if parts.fragment else f"hysteria2_{server}"; params = {k: v[0] for k, v in parse_qs(parts.query).items()};
        return {'name': remarks, 'type': 'hysteria2', 'server': server, 'port': int(port), 'password': password, 'sni': params.get('sni', server), 'skip-cert-verify': params.get('insecure', '0') == '1'}
    except: return None

# # Xray
# def generate_xray_config(node):
#     protocol_map = {'ss': 'shadowsocks', 'vmess': 'vmess', 'vless': 'vless', 'trojan': 'trojan'}
#     xray_protocol = protocol_map.get(node['type'])
#     if not xray_protocol: raise ValueError(f"不支持的节点类型: {node['type']}")
#     if node['type'] == 'trojan': outbound_settings = {"servers": [{"address": node['server'], "port": node['port'], "password": node['password']}]}
#     else:
#         outbound_settings = {"vnext": [{"address": node['server'], "port": node['port'], "users": []}]}
#         if node['type'] == 'vmess': outbound_settings['vnext'][0]['users'].append({"id": node['uuid'], "alterId": node.get('alterId', 0), "security": node.get('cipher', 'auto')})
#         elif node['type'] == 'vless': outbound_settings['vnext'][0]['users'].append({"id": node['uuid'], "flow": node.get('flow', ''), "encryption": "none"})
#         elif node['type'] == 'ss': outbound_settings['vnext'][0]['users'].append({"method": node['cipher'], "password": node['password']})
#     stream_settings = {"network": node.get('network', 'tcp')}
#     if node.get('tls', False): stream_settings['security'] = 'tls'; stream_settings['tlsSettings'] = {"serverName": node.get('servername', node.get('sni', node['server']))}
#     if node.get('network') == 'ws':
#         ws_opts = node.get('ws-opts', {}); ws_headers = ws_opts.get('headers', {}); host = ws_headers.get('Host')
#         stream_settings['wsSettings'] = {"path": ws_opts.get('path', '/')}
#         if host: stream_settings['wsSettings']['host'] = host
#     return {"inbounds": [{"port": LOCAL_SOCKS_PORT, "listen": "127.0.0.1", "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}], "outbounds": [{"protocol": xray_protocol, "settings": outbound_settings, "streamSettings": stream_settings}]}


# def test_node_latency(node):
#     try:
#         addr = (node['server'], int(node['port'])); start_time = time.time()
#         with socket.create_connection(addr, timeout=TCP_PING_TIMEOUT):
#             tcp_latency = int((time.time() - start_time) * 1000)
#             print(f"TCP Ping 通 ({tcp_latency}ms)，进行深度测试...", end="")
#     except (socket.timeout, ConnectionRefusedError, OSError):
#         print("TCP Ping 失败", end=""); return -1

#     if node['type'] in ['hysteria', 'hysteria2']: return tcp_latency

#     try:
#         config = generate_xray_config(node)
#         with open(XRAY_CONFIG_FILE, 'w') as f: json.dump(config, f)
#     except Exception as e:
#         print(f"生成配置失败: {e}", end=""); return -1

#     process = None
#     try:
#         # --- 诊断改动：捕获 stderr ---
#         process = subprocess.Popen(
#             [XRAY_PATH, 'run', '-c', XRAY_CONFIG_FILE],
#             stdout=subprocess.DEVNULL,
#             stderr=subprocess.PIPE, # 将错误输出重定向到管道
#             text=True # 让 stderr.read() 返回字符串
#         )
#         time.sleep(1.5)

#         # 检查 Xray 进程是否已退出
#         if process.poll() is not None:
#             # --- 诊断改动：读取并打印错误日志 ---
#             error_log = process.stderr.read()
#             print(f"Xray 进程启动失败，错误日志:\n---\n{error_log.strip()}\n---", end="")
#             return -1
        
#         proxies = {'http': f'socks5h://127.0.0.1:{LOCAL_SOCKS_PORT}', 'https': f'socks5h://127.0.0.1:{LOCAL_SOCKS_PORT}'}
#         start_time = time.time()
#         response = requests.get(REAL_TEST_URL, proxies=proxies, timeout=REAL_TEST_TIMEOUT)
#         end_time = time.time()
        
#         if response.status_code == 200: return int((end_time - start_time) * 1000)
#         else: return -1
#     except requests.exceptions.RequestException: return -1
#     finally:
#         if process: process.terminate(); process.wait()
#         if os.path.exists(XRAY_CONFIG_FILE): os.remove(XRAY_CONFIG_FILE)

# def test_node_latency(node):
#     """
#     仅通过 TCP Ping 测试节点的延迟。
#     返回毫秒延迟或 -1 (失败)。
#     """
#     try:
#         addr = (node['server'], int(node['port']))
#         start_time = time.time()
#         with socket.create_connection(addr, timeout=TCP_PING_TIMEOUT):
#             end_time = time.time()
#         latency = int((end_time - start_time) * 1000)
#         return latency
#     except (socket.timeout, ConnectionRefusedError, OSError):
#         return -1
def test_node_latency(node):
    """
    Tests node latency using the system's ping command.
    Returns latency in milliseconds, or -1 on failure.
    """
    host = node.get('server')
    if not host:
        return -1

    # Determine the appropriate ping command based on the operating system
    system = platform.system()
    if system == "Windows":
        # -n 1: Send 1 ICMP echo request.
        # -w 3000: Wait 3000 milliseconds (3 seconds) for a reply.
        command = ["ping", "-n", "1", "-w", "1000", host]
    else: # For Linux, macOS, and other UNIX-like systems
        # -c 1: Send 1 ICMP echo request.
        # -W 3: Wait 3 seconds for a reply.
        command = ["ping", "-c", "1", "-W", "1", host]

    try:
        # Execute the ping command
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5  # A safety timeout for the subprocess itself
        )

        # Check if the ping command was successful
        if result.returncode != 0:
            return -1

        # Use regular expressions to parse the latency from the command's output
        output = result.stdout
        # This regex is designed to be compatible with both Windows and Linux/macOS output
        match = re.search(r"time(?:[=<])([\d.]+)\s*ms", output)
        
        # For some Windows locales, the average time is the most reliable metric
        if system == "Windows" and not match:
            match = re.search(r"Average = ([\d.]+)\s*ms", output)

        if match:
            latency = float(match.group(1))
            return int(latency)
        else:
            return -1

    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return -1


def main():
    if not os.path.exists(XRAY_PATH): print("错误: Xray-core 可执行文件未找到。"); return
    with open(SUBSCRIPTION_URLS_FILE, 'r', encoding='utf-8') as f:
        subscription_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    print(f"找到 {len(subscription_urls)} 个订阅链接。")
    all_nodes, unique_nodes = [], set()
    for url in subscription_urls:
        content = get_subscription_content(url)
        if not content: continue
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict) and 'proxies' in data and isinstance(data['proxies'], list):
                print(f"内容识别为 YAML，找到 {len(data['proxies'])} 个代理。")
                for proxy in data['proxies']:
                    if all(k in proxy for k in ['name', 'server', 'port', 'type']):
                        try: proxy['port'] = int(proxy['port'])
                        except (ValueError, TypeError): continue
                        node_id = (proxy['server'], proxy['port'], proxy['type'])
                        if node_id not in unique_nodes: all_nodes.append(proxy); unique_nodes.add(node_id)
                continue
        except: pass
        links_content = None
        if any(p in content for p in ["ss://", "vmess://", "trojan://", "vless://", "hysteria://", "hysteria2://"]):
            print("内容识别为明文链接。"); links_content = content
        else: print("内容识别为潜在的 Base64，尝试解码。"); links_content = decode_base64_content(content)
        if not links_content: print("无法从此 URL 解析。\n"); continue
        for link in links_content.splitlines():
            node = parse_node(link)
            if node:
                node_id = (node['server'], node['port'], node['type'])
                if node_id not in unique_nodes: all_nodes.append(node); unique_nodes.add(node_id)
        print("")
    print(f"去重后共解析出 {len(all_nodes)} 个节点。")
    fast_nodes = []
    print("\n--- 开始节点延迟测试 ---")
    for i, node in enumerate(all_nodes):
        print(f"({i+1}/{len(all_nodes)}) 测试节点: {node['name']:<40} ... ", end="")
        latency = test_node_latency(node)
        if 0 < latency < MAX_LATENCY_MS: print(f"延迟: {latency}ms [通过]"); fast_nodes.append(node)
        else: print(f"延迟: {latency if latency > 0 else '失败'} [丢弃]")
    print("--- 延迟测试结束 ---\n")
    print(f"筛选出 {len(fast_nodes)} 个可用节点。")
    clash_config = {'proxies': fast_nodes}
    with open(OUTPUT_CLASH_FILE, 'w', encoding='utf-8') as f: yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
    print(f"成功生成 Clash 订阅文件: {OUTPUT_CLASH_FILE}")
    with open(UPDATE_TIME_FILE, 'w', encoding='utf-8') as f:
        update_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        f.write(f"最后更新时间: {update_time}\n"); f.write(f"可用节点数量: {len(fast_nodes)}\n")
    print(f"成功记录时间: {UPDATE_TIME_FILE}")

if __name__ == '__main__':
    main()
