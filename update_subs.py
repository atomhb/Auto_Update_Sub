import base64
import json
import os
import requests
import socket
import time
import yaml
import binascii
import subprocess
from datetime import datetime
from urllib.parse import unquote, urlparse, parse_qs

# --- 配置 ---
# 订阅链接文件路径
SUBSCRIPTION_URLS_FILE = 'sub_urls.txt'
# 输出的 Clash 订阅文件路径
OUTPUT_CLASH_FILE = 'update_subs.yaml'
# 输出的更新时间记录文件路径
UPDATE_TIME_FILE = 'update_time.txt'
MAX_LATENCY_MS = 500
# 真实延迟测试相关配置
REAL_TEST_URL = 'https://www.gstatic.com/generate_204'
REAL_TEST_TIMEOUT = 5  # 秒
XRAY_PATH = './xray'  # Xray-core 可执行文件路径
XRAY_CONFIG_FILE = 'xray_config.json'
LOCAL_SOCKS_PORT = 10808 # Xray 监听的本地 SOCKS 端口

def get_subscription_content(url):
    """通过 URL 获取订阅内容。"""
    headers = {'User-Agent': 'Clash/1.11.0'}
    try:
        print(f"正在获取订阅: {url}")
        response = requests.get(url, timeout=15, headers=headers)
        response.raise_for_status()
        # 统一使用 utf-8 编码读取
        response.encoding = 'utf-8'
        return response.text
    except requests.RequestException as e:
        print(f"获取订阅失败: {url}, 错误: {e}")
        return None

def decode_base64_content(content):
    """
    解码 Base64 编码的订阅内容。
    增加错误捕获，防止因非 Base64 字符导致程序崩溃。
    """
    try:
        missing_padding = len(content) % 4
        if missing_padding:
            content += '=' * (4 - missing_padding)
        # 先将字符串编码为 ascii，再进行 base64 解码
        decoded_bytes = base64.b64decode(content.encode('ascii'))
        return decoded_bytes.decode('utf-8')
    except (binascii.Error, UnicodeDecodeError, ValueError) as e:
        print(f"Base64 解码失败: {e}")
        return None

# <--- 此处省略了所有 parse_..._link 函数，它们与上一版本相同 --->
# <--- 请确保您的文件中保留了这些解析函数 --->
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
        parts = urlparse(ss_link); user_info, host_info = parts.netloc.split('@'); server, port = host_info.split(':')
        try: decoded_user_info = base64.b64decode(user_info).decode('utf-8'); method, password = decoded_user_info.split(':', 1)
        except: user_info = unquote(user_info); method, password = user_info.split(':', 1)
        remarks = unquote(parts.fragment) if parts.fragment else f"ss_{server}"
        return {'name': remarks, 'type': 'ss', 'server': server, 'port': int(port), 'cipher': method, 'password': password, 'udp': True}
    except Exception as e: print(f"解析 SS 链接失败: {ss_link}, 错误: {e}"); return None
def parse_vmess_link(vmess_link):
    try:
        if len(vmess_link[8:]) % 4 != 0: vmess_link += '=' * (4 - len(vmess_link[8:]) % 4)
        decoded_link = base64.b64decode(vmess_link[8:]).decode('utf-8'); vmess_data = json.loads(decoded_link)
        node = {'name': vmess_data.get('ps', vmess_data.get('add')), 'type': 'vmess', 'server': vmess_data.get('add'), 'port': int(vmess_data.get('port')), 'uuid': vmess_data.get('id'), 'alterId': int(vmess_data.get('aid')), 'cipher': vmess_data.get('scy', 'auto'), 'udp': True, 'tls': vmess_data.get('tls') == 'tls', 'network': vmess_data.get('net')}
        if node['tls']: node['servername'] = vmess_data.get('sni', vmess_data.get('host', ''))
        if node['network'] == 'ws': node['ws-opts'] = {'path': vmess_data.get('path', '/'), 'headers': {'Host': vmess_data.get('host')} if vmess_data.get('host') else {}}
        return node
    except Exception as e: print(f"解析 Vmess 链接失败: {vmess_link}, 错误: {e}"); return None
def parse_trojan_link(trojan_link):
    try:
        parts = urlparse(trojan_link); password, host_info = parts.netloc.split('@'); server, port = host_info.split(':')
        remarks = unquote(parts.fragment) if parts.fragment else f"trojan_{server}"; params = {k: v[0] for k, v in parse_qs(parts.query).items()}
        return {'name': remarks, 'type': 'trojan', 'server': server, 'port': int(port), 'password': password, 'udp': True, 'sni': params.get('sni', server), 'skip-cert-verify': params.get('allowInsecure', 'false').lower() in ['true', '1']}
    except Exception as e: print(f"解析 Trojan 链接失败: {trojan_link}, 错误: {e}"); return None
def parse_vless_link(vless_link):
    try:
        parts = urlparse(vless_link); uuid, host_info = parts.netloc.split('@'); server, port = host_info.split(':')
        remarks = unquote(parts.fragment) if parts.fragment else f"vless_{server}"; params = {k: v[0] for k, v in parse_qs(parts.query).items()}
        node = {'name': remarks, 'type': 'vless', 'server': server, 'port': int(port), 'uuid': uuid, 'udp': True, 'tls': params.get('security') == 'tls', 'network': params.get('type', 'tcp'), 'servername': params.get('sni', server), 'flow': params.get('flow', '')}
        if node['network'] == 'ws': node['ws-opts'] = {'path': params.get('path', '/'), 'headers': {'Host': params.get('host', server)}}
        elif node['network'] == 'grpc': node['grpc-opts'] = {'grpc-service-name': params.get('serviceName', '')}
        return node
    except Exception as e: print(f"解析 VLESS 链接失败: {vless_link}, 错误: {e}"); return None
def parse_hysteria_link(hy_link):
    try:
        parts = urlparse(hy_link); server, port = parts.netloc.split(':'); remarks = unquote(parts.fragment) if parts.fragment else f"hysteria_{server}"; params = {k: v[0] for k, v in parse_qs(parts.query).items()}
        return {'name': remarks, 'type': 'hysteria', 'server': server, 'port': int(port), 'protocol': params.get('protocol', 'udp'), 'auth_str': params.get('auth'), 'up': int(params.get('upmbps', 50)), 'down': int(params.get('downmbps', 100)), 'sni': params.get('peer', server), 'skip-cert-verify': params.get('insecure', '0') == '1'}
    except Exception as e: print(f"解析 Hysteria 链接失败: {hy_link}, 错误: {e}"); return None
def parse_hysteria2_link(hy2_link):
    try:
        parts = urlparse(hy2_link); password, host_info = parts.netloc.split('@'); server, port = host_info.split(':')
        remarks = unquote(parts.fragment) if parts.fragment else f"hysteria2_{server}"; params = {k: v[0] for k, v in parse_qs(parts.query).items()}
        return {'name': remarks, 'type': 'hysteria2', 'server': server, 'port': int(port), 'password': password, 'sni': params.get('sni', server), 'skip-cert-verify': params.get('insecure', '0') == '1'}
    except Exception as e: print(f"解析 Hysteria2 链接失败: {hy2_link}, 错误: {e}"); return None


def generate_xray_config(node):
    # ... 此函数与上一版本相同 ...
    if node['type'] not in ['vmess', 'vless', 'trojan', 'ss']: raise ValueError(f"不支持的节点类型: {node['type']}")
    outbound_settings = {"vnext": [{"address": node['server'], "port": node['port'], "users": []}]}
    if node['type'] == 'vmess': outbound_settings['vnext'][0]['users'].append({"id": node['uuid'], "alterId": node.get('alterId', 0), "security": node.get('cipher', 'auto')})
    elif node['type'] == 'vless': outbound_settings['vnext'][0]['users'].append({"id": node['uuid'], "flow": node.get('flow', ''), "encryption": "none"})
    elif node['type'] == 'trojan': outbound_settings['vnext'][0]['users'].append({"password": node['password']})
    elif node['type'] == 'ss': outbound_settings['vnext'][0]['users'].append({"method": node['cipher'], "password": node['password']})
    stream_settings = {"network": node.get('network', 'tcp')}
    if node.get('tls', False): stream_settings['security'] = 'tls'; stream_settings['tlsSettings'] = {"serverName": node.get('servername', node.get('sni', node['server']))}
    if node.get('network') == 'ws': stream_settings['wsSettings'] = {"path": node.get('ws-opts', {}).get('path', '/'), "headers": node.get('ws-opts', {}).get('headers', {})}
    return {"inbounds": [{"port": LOCAL_SOCKS_PORT, "listen": "127.0.0.1", "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}], "outbounds": [{"protocol": node['type'], "settings": outbound_settings, "streamSettings": stream_settings}]}

def test_node_real_latency(node):
    # ... 此函数与上一版本相同 ...
    if node['type'] in ['hysteria', 'hysteria2']:
        try:
            addr = (node['server'], int(node['port'])); start_time = time.time()
            with socket.create_connection(addr, timeout=REAL_TEST_TIMEOUT / 2): end_time = time.time()
            return int((end_time - start_time) * 1000)
        except (socket.timeout, ConnectionRefusedError, OSError): return -1
    try:
        config = generate_xray_config(node)
        with open(XRAY_CONFIG_FILE, 'w') as f: json.dump(config, f)
    except Exception as e: print(f"生成配置失败: {e}", end=""); return -1
    process = None
    try:
        process = subprocess.Popen([XRAY_PATH, 'run', '-c', XRAY_CONFIG_FILE])
        time.sleep(1.5)
        proxies = {'http': f'socks5h://127.0.0.1:{LOCAL_SOCKS_PORT}', 'https': f'socks5h://127.0.0.1:{LOCAL_SOCKS_PORT}'}
        start_time = time.time(); response = requests.get(REAL_TEST_URL, proxies=proxies, timeout=REAL_TEST_TIMEOUT); end_time = time.time()
        if response.status_code == 204: return int((end_time - start_time) * 1000)
        else: return -1
    except requests.exceptions.RequestException: return -1
    finally:
        if process: process.terminate(); process.wait()
        if os.path.exists(XRAY_CONFIG_FILE): os.remove(XRAY_CONFIG_FILE)

def main():
    """主函数"""
    if not os.path.exists(XRAY_PATH):
        print("错误: Xray-core 可执行文件未找到。")
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

        nodes_from_url = []
        
        # --- 核心修复逻辑 ---
        # 1. 尝试将内容作为 Clash YAML 配置解析
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict) and 'proxies' in data and isinstance(data['proxies'], list):
                print(f"内容识别为 YAML/Clash 配置，找到 {len(data['proxies'])} 个代理。")
                for proxy in data['proxies']:
                    if all(k in proxy for k in ['name', 'server', 'port', 'type']):
                        nodes_from_url.append(proxy)
                
                for node in nodes_from_url:
                    node_id = (node['server'], node['port'], node['type'])
                    if node_id not in unique_nodes:
                        all_nodes.append(node)
                        unique_nodes.add(node_id)
                continue # 已成功解析 YAML，处理下一个 URL
        except (yaml.YAMLError, AttributeError):
            # 不是有效的 YAML，继续尝试其他方法
            pass
        # --- 修复逻辑结束 ---

        # 2. 如果不是YAML，检查是否为明文链接列表
        links_content = None
        if any(proto in content for proto in ["ss://", "vmess://", "trojan://", "vless://", "hysteria://", "hysteria2://"]):
            print("内容识别为明文链接列表。")
            links_content = content
        # 3. 否则，最后尝试作为 Base64 解码
        else:
            print("内容识别为潜在的 Base64 编码，尝试解码。")
            links_content = decode_base64_content(content)

        if not links_content:
            print("无法从此 URL 解析任何链接。\n")
            continue

        # 解析链接内容
        links = links_content.splitlines()
        for link in links:
            node = parse_node(link)
            if node:
                node_id = (node['server'], node['port'], node['type'])
                if node_id not in unique_nodes:
                    all_nodes.append(node)
                    unique_nodes.add(node_id)
        print("") # 换行

    print(f"去重后共解析出 {len(all_nodes)} 个节点。")

    fast_nodes = []
    print("\n--- 开始节点真实延迟测试 ---")
    for i, node in enumerate(all_nodes):
        latency = test_node_real_latency(node)
        print(f"({i+1}/{len(all_nodes)}) 测试节点: {node['name']:<40} ... ", end="")
        if 0 < latency < MAX_LATENCY_MS:
            print(f"延迟: {latency}ms [通过]")
            fast_nodes.append(node)
        else:
            print(f"延迟: {latency if latency > 0 else '超时或失败'} [丢弃]")
    print("--- 延迟测试结束 ---\n")
            
    print(f"筛选出 {len(fast_nodes)} 个可用节点。")

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
