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
# Timeout for the real latency test request
REQUEST_TIMEOUT = 10

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


# --- NEW LATENCY TEST FUNCTION ---
def test_node_latency(node):
    """
    Tests node latency by making a real HTTP request to REAL_TEST_URL through it.

    This method uses the `requests` library to measure latency. It attempts to treat
    the node as a standard HTTP or SOCKS proxy.

    *** IMPORTANT LIMITATION ***
    Protocols like Vmess, VLESS, Trojan, and Shadowsocks are NOT standard proxies
    that the `requests` library can use directly. For this function to work, you
    need a client program that understands the specific protocol and provides a
    standard proxy interface (e.g., a local SOCKS5 port).

    This function is provided to demonstrate the requested logic but will likely
    fail for most node types, returning -1. The most reliable test method without
    a full Python client library is a simple TCP ping to check port reachability.
    """
    server = node.get('server')
    port = node.get('port')

    if not server or not port:
        return -1

    # We formulate a proxy URL. This is a significant simplification.
    # It assumes the remote server is a standard SOCKS5 proxy, which is unlikely.
    # Note: Using SOCKS proxies requires installing the `PySocks` library:
    # `pip install "requests[socks]"`
    proxy_url = f"socks5h://{server}:{port}"

    proxies = {
        'http': proxy_url,
        'https': proxy_url
    }

    try:
        start_time = time.time()
        
        # Make the request through the specified proxy
        response = requests.get(REAL_TEST_URL, proxies=proxies, timeout=REQUEST_TIMEOUT)
        
        end_time = time.time()

        # Check for a successful response (status code 2xx)
        response.raise_for_status()
        
        latency_ms = int((end_time - start_time) * 1000)
        return latency_ms

    except (requests.exceptions.ProxyError,
            requests.exceptions.ConnectTimeout,
            requests.exceptions.ReadTimeout,
            requests.exceptions.RequestException):
        # This block catches most errors related to failed proxy connections,
        # which is the expected outcome for unsupported custom protocols.
        return -1
    except Exception:
        # Catch any other unexpected errors
        return -1


def main():
    # The XRAY_PATH check is no longer needed with the new test function
    # if not os.path.exists(XRAY_PATH): print("错误: Xray-core 可执行文件未找到。"); return
    
    with open(SUBSCRIPTION_URLS_FILE, 'r', encoding='utf-8') as f:
        subscription_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    print(f"找到 {len(subscription_urls)} 个订阅链接。")
    all_nodes, unique_nodes = [], set()
    
    for url in subscription_urls:
        content = get_subscription_content(url)
        if not content: continue
        
        # Try parsing as YAML (Clash format)
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict) and 'proxies' in data and isinstance(data['proxies'], list):
                print(f"内容识别为 YAML，找到 {len(data['proxies'])} 个代理。")
                for proxy in data['proxies']:
                    if all(k in proxy for k in ['name', 'server', 'port', 'type']):
                        try:
                            proxy['port'] = int(proxy['port'])
                        except (ValueError, TypeError):
                            continue
                        node_id = (proxy['server'], proxy['port'], proxy['type'])
                        if node_id not in unique_nodes:
                            all_nodes.append(proxy)
                            unique_nodes.add(node_id)
                continue
        except:
            pass
        
        # Try parsing as plain text or Base64 encoded links
        links_content = None
        if any(p in content for p in ["ss://", "vmess://", "trojan://", "vless://", "hysteria://", "hysteria2://"]):
            print("内容识别为明文链接。")
            links_content = content
        else:
            print("内容识别为潜在的 Base64，尝试解码。")
            links_content = decode_base64_content(content)
        
        if not links_content:
            print("无法从此 URL 解析。\n")
            continue
            
        for link in links_content.splitlines():
            node = parse_node(link)
            if node:
                node_id = (node['server'], node['port'], node['type'])
                if node_id not in unique_nodes:
                    all_nodes.append(node)
                    unique_nodes.add(node_id)
        print("")
        
    print(f"去重后共解析出 {len(all_nodes)} 个节点。")
    fast_nodes = []
    
    print("\n--- 开始节点延迟测试 ---")
    for i, node in enumerate(all_nodes):
        print(f"({i+1}/{len(all_nodes)}) 测试节点: {node['name']:<40} ... ", end="")
        latency = test_node_latency(node)
        if 0 < latency < MAX_LATENCY_MS:
            print(f"延迟: {latency}ms [通过]")
            fast_nodes.append(node)
        else:
            print(f"延迟: {latency if latency > 0 else '失败'} [丢弃]")
    print("--- 延迟测试结束 ---\n")
    
    print(f"筛选出 {len(fast_nodes)} 个可用节点。")

    clash_config = {
        'port': 7890,
        'allow-lan': False,
        'mode': 'rule',
        'external-controller': '127.0.0.1:9090',
        'dns': {
            'enabled': True,
            'enhanced-mode': 'fake-ip',
            'fake-ip-range': '198.18.0.1/16',
            'nameserver': [
                'https://doh.pub/dns-query',
                'https://223.5.5.5/dns-query',
                'https://doh.360.cn/dns-query',
                'https://dns.alidns.com/dns-query',
                '119.29.29.29'
            ],
            'fallback': [
                '8.8.8.8',
                '8.8.4.4',
                'tls://1.0.0.1:853',
                'tls://dns.google:853'
            ]
        }
    }

    clash_config['proxies'] = fast_nodes
    
    proxy_names = [node['name'] for node in fast_nodes]
    
    clash_config['proxy-groups'] = [
        {
            'name': '⭕ proxinode',
            'type': 'select',
            'proxies': ['♻️ automatic'] + proxy_names
        },
        {
            'name': '♻️ automatic',
            'type': 'url-test',
            'proxies': proxy_names,
            'url': 'https://www.google.com/favicon.ico',
            'interval': 300
        }
    ]

    clash_config['rules'] = [
        'DOMAIN,safebrowsing.urlsec.qq.com,DIRECT', 'DOMAIN,safebrowsing.googleapis.com,DIRECT', 'DOMAIN,developer.apple.com,⭕ proxinode',
        'DOMAIN-SUFFIX,digicert.com,⭕ proxinode', 'DOMAIN,ocsp.apple.com,⭕ proxinode', 'DOMAIN,ocsp.comodoca.com,⭕ proxinode', 'DOMAIN,ocsp.usertrust.com,⭕ proxinode',
        'DOMAIN,ocsp.sectigo.com,⭕ proxinode', 'DOMAIN,ocsp.verisign.net,⭕ proxinode', 'DOMAIN-SUFFIX,apple-dns.net,⭕ proxinode', 'DOMAIN,testflight.apple.com,⭕ proxinode',
        'DOMAIN,sandbox.itunes.apple.com,⭕ proxinode', 'DOMAIN,itunes.apple.com,⭕ proxinode', 'DOMAIN-SUFFIX,apps.apple.com,⭕ proxinode', 'DOMAIN-SUFFIX,blobstore.apple.com,⭕ proxinode',
        'DOMAIN,cvws.icloud-content.com,⭕ proxinode', 'DOMAIN-SUFFIX,mzstatic.com,DIRECT', 'DOMAIN-SUFFIX,itunes.apple.com,DIRECT', 'DOMAIN-SUFFIX,icloud.com,DIRECT',
        'DOMAIN-SUFFIX,icloud-content.com,DIRECT', 'DOMAIN-SUFFIX,me.com,DIRECT', 'DOMAIN-SUFFIX,aaplimg.com,DIRECT', 'DOMAIN-SUFFIX,cdn20.com,DIRECT',
        'DOMAIN-SUFFIX,cdn-apple.com,DIRECT', 'DOMAIN-SUFFIX,akadns.net,DIRECT', 'DOMAIN-SUFFIX,akamaiedge.net,DIRECT', 'DOMAIN-SUFFIX,edgekey.net,DIRECT',
        'DOMAIN-SUFFIX,mwcloudcdn.com,DIRECT', 'DOMAIN-SUFFIX,mwcname.com,DIRECT', 'DOMAIN-SUFFIX,apple.com,DIRECT', 'DOMAIN-SUFFIX,apple-cloudkit.com,DIRECT',
        'DOMAIN-SUFFIX,apple-mapkit.com,DIRECT', 'DOMAIN-SUFFIX,cn,DIRECT', 'DOMAIN-KEYWORD,-cn,DIRECT', 'DOMAIN-SUFFIX,126.com,DIRECT', 'DOMAIN-SUFFIX,126.net,DIRECT',
        'DOMAIN-SUFFIX,127.net,DIRECT', 'DOMAIN-SUFFIX,163.com,DIRECT', 'DOMAIN-SUFFIX,360buyimg.com,DIRECT', 'DOMAIN-SUFFIX,36kr.com,DIRECT', 'DOMAIN-SUFFIX,acfun.tv,DIRECT',
        'DOMAIN-SUFFIX,air-matters.com,DIRECT', 'DOMAIN-SUFFIX,aixifan.com,DIRECT', 'DOMAIN-KEYWORD,alicdn,DIRECT', 'DOMAIN-KEYWORD,alipay,DIRECT', 'DOMAIN-KEYWORD,taobao,DIRECT',
        'DOMAIN-SUFFIX,amap.com,DIRECT', 'DOMAIN-SUFFIX,autonavi.com,DIRECT', 'DOMAIN-KEYWORD,baidu,DIRECT', 'DOMAIN-SUFFIX,bdimg.com,DIRECT', 'DOMAIN-SUFFIX,bdstatic.com,DIRECT',
        'DOMAIN-SUFFIX,bilibili.com,DIRECT', 'DOMAIN-SUFFIX,bilivideo.com,DIRECT', 'DOMAIN-SUFFIX,caiyunapp.com,DIRECT', 'DOMAIN-SUFFIX,clouddn.com,DIRECT',
        'DOMAIN-SUFFIX,cnbeta.com,DIRECT', 'DOMAIN-SUFFIX,cnbetacdn.com,DIRECT', 'DOMAIN-SUFFIX,cootekservice.com,DIRECT', 'DOMAIN-SUFFIX,csdn.net,DIRECT',
        'DOMAIN-SUFFIX,ctrip.com,DIRECT', 'DOMAIN-SUFFIX,dgtle.com,DIRECT', 'DOMAIN-SUFFIX,dianping.com,DIRECT', 'DOMAIN-SUFFIX,douban.com,DIRECT',
        'DOMAIN-SUFFIX,doubanio.com,DIRECT', 'DOMAIN-SUFFIX,duokan.com,DIRECT', 'DOMAIN-SUFFIX,easou.com,DIRECT', 'DOMAIN-SUFFIX,ele.me,DIRECT', 'DOMAIN-SUFFIX,feng.com,DIRECT',
        'DOMAIN-SUFFIX,fir.im,DIRECT', 'DOMAIN-SUFFIX,frdic.com,DIRECT', 'DOMAIN-SUFFIX,g-cores.com,DIRECT', 'DOMAIN-SUFFIX,godic.net,DIRECT', 'DOMAIN-SUFFIX,gtimg.com,DIRECT',
        'DOMAIN,cdn.hockeyapp.net,DIRECT', 'DOMAIN-SUFFIX,hongxiu.com,DIRECT', 'DOMAIN-SUFFIX,hxcdn.net,DIRECT', 'DOMAIN-SUFFIX,iciba.com,DIRECT', 'DOMAIN-SUFFIX,ifeng.com,DIRECT',
        'DOMAIN-SUFFIX,ifengimg.com,DIRECT', 'DOMAIN-SUFFIX,ipip.net,DIRECT', 'DOMAIN-SUFFIX,iqiyi.com,DIRECT', 'DOMAIN-SUFFIX,jd.com,DIRECT', 'DOMAIN-SUFFIX,jianshu.com,DIRECT',
        'DOMAIN-SUFFIX,knewone.com,DIRECT', 'DOMAIN-SUFFIX,le.com,DIRECT', 'DOMAIN-SUFFIX,lecloud.com,DIRECT', 'DOMAIN-SUFFIX,lemicp.com,DIRECT', 'DOMAIN-SUFFIX,licdn.com,DIRECT',
        'DOMAIN-SUFFIX,luoo.net,DIRECT', 'DOMAIN-SUFFIX,meituan.com,DIRECT', 'DOMAIN-SUFFIX,meituan.net,DIRECT', 'DOMAIN-SUFFIX,mi.com,DIRECT', 'DOMAIN-SUFFIX,miaopai.com,DIRECT',
        'DOMAIN-SUFFIX,microsoft.com,DIRECT', 'DOMAIN-SUFFIX,microsoftonline.com,DIRECT', 'DOMAIN-SUFFIX,miui.com,DIRECT', 'DOMAIN-SUFFIX,miwifi.com,DIRECT',
        'DOMAIN-SUFFIX,mob.com,DIRECT', 'DOMAIN-SUFFIX,netease.com,DIRECT', 'DOMAIN-SUFFIX,office.com,DIRECT', 'DOMAIN-SUFFIX,office365.com,DIRECT', 'DOMAIN-KEYWORD,officecdn,DIRECT',
        'DOMAIN-SUFFIX,oschina.net,DIRECT', 'DOMAIN-SUFFIX,ppsimg.com,DIRECT', 'DOMAIN-SUFFIX,pstatp.com,DIRECT', 'DOMAIN-SUFFIX,qcloud.com,DIRECT', 'DOMAIN-SUFFIX,qdaily.com,DIRECT',
        'DOMAIN-SUFFIX,qdmm.com,DIRECT', 'DOMAIN-SUFFIX,qhimg.com,DIRECT', 'DOMAIN-SUFFIX,qhres.com,DIRECT', 'DOMAIN-SUFFIX,qidian.com,DIRECT', 'DOMAIN-SUFFIX,qihucdn.com,DIRECT',
        'DOMAIN-SUFFIX,qiniu.com,DIRECT', 'DOMAIN-SUFFIX,qiniucdn.com,DIRECT', 'DOMAIN-SUFFIX,qiyipic.com,DIRECT', 'DOMAIN-SUFFIX,qq.com,DIRECT', 'DOMAIN-SUFFIX,qqurl.com,DIRECT',
        'DOMAIN-SUFFIX,rarbg.to,DIRECT', 'DOMAIN-SUFFIX,ruguoapp.com,DIRECT', 'DOMAIN-SUFFIX,segmentfault.com,DIRECT', 'DOMAIN-SUFFIX,sinaapp.com,DIRECT',
        'DOMAIN-SUFFIX,smzdm.com,DIRECT', 'DOMAIN-SUFFIX,snapdrop.net,DIRECT', 'DOMAIN-SUFFIX,sogou.com,DIRECT', 'DOMAIN-SUFFIX,sogoucdn.com,DIRECT', 'DOMAIN-SUFFIX,sohu.com,DIRECT',
        'DOMAIN-SUFFIX,soku.com,DIRECT', 'DOMAIN-SUFFIX,speedtest.net,⭕ proxinode', 'DOMAIN-SUFFIX,sspai.com,DIRECT', 'DOMAIN-SUFFIX,suning.com,DIRECT', 'DOMAIN-SUFFIX,taobao.com,DIRECT',
        'DOMAIN-SUFFIX,tencent.com,DIRECT', 'DOMAIN-SUFFIX,tenpay.com,DIRECT', 'DOMAIN-SUFFIX,tianyancha.com,DIRECT', 'DOMAIN-SUFFIX,tmall.com,DIRECT', 'DOMAIN-SUFFIX,tudou.com,DIRECT',
        'DOMAIN-SUFFIX,umetrip.com,DIRECT', 'DOMAIN-SUFFIX,upaiyun.com,DIRECT', 'DOMAIN-SUFFIX,upyun.com,DIRECT', 'DOMAIN-SUFFIX,veryzhun.com,DIRECT', 'DOMAIN-SUFFIX,weather.com,DIRECT',
        'DOMAIN-SUFFIX,weibo.com,DIRECT', 'DOMAIN-SUFFIX,xiami.com,DIRECT', 'DOMAIN-SUFFIX,xiami.net,DIRECT', 'DOMAIN-SUFFIX,xiaomicp.com,DIRECT', 'DOMAIN-SUFFIX,ximalaya.com,DIRECT',
        'DOMAIN-SUFFIX,xmcdn.com,DIRECT', 'DOMAIN-SUFFIX,xunlei.com,DIRECT', 'DOMAIN-SUFFIX,yhd.com,DIRECT', 'DOMAIN-SUFFIX,yihaodianimg.com,DIRECT', 'DOMAIN-SUFFIX,yinxiang.com,DIRECT',
        'DOMAIN-SUFFIX,ykimg.com,DIRECT', 'DOMAIN-SUFFIX,youdao.com,DIRECT', 'DOMAIN-SUFFIX,youku.com,DIRECT', 'DOMAIN-SUFFIX,zealer.com,DIRECT', 'DOMAIN-SUFFIX,zhihu.com,DIRECT',
        'DOMAIN-SUFFIX,zhimg.com,DIRECT', 'DOMAIN-SUFFIX,zimuzu.tv,DIRECT', 'DOMAIN-SUFFIX,zoho.com,DIRECT', 'DOMAIN-KEYWORD,amazon,⭕ proxinode', 'DOMAIN-KEYWORD,google,⭕ proxinode',
        'DOMAIN-KEYWORD,gmail,⭕ proxinode', 'DOMAIN-KEYWORD,youtube,⭕ proxinode', 'DOMAIN-KEYWORD,facebook,⭕ proxinode', 'DOMAIN-SUFFIX,fb.me,⭕ proxinode',
        'DOMAIN-SUFFIX,fbcdn.net,⭕ proxinode', 'DOMAIN-KEYWORD,twitter,⭕ proxinode', 'DOMAIN-KEYWORD,instagram,⭕ proxinode', 'DOMAIN-KEYWORD,dropbox,⭕ proxinode',
        'DOMAIN-SUFFIX,twimg.com,⭕ proxinode', 'DOMAIN-KEYWORD,blogspot,⭕ proxinode', 'DOMAIN-SUFFIX,youtu.be,⭕ proxinode', 'DOMAIN-KEYWORD,whatsapp,⭕ proxinode',
        'DOMAIN-KEYWORD,admarvel,REJECT', 'DOMAIN-KEYWORD,admaster,REJECT', 'DOMAIN-KEYWORD,adsage,REJECT', 'DOMAIN-KEYWORD,adsmogo,REJECT', 'DOMAIN-KEYWORD,adsrvmedia,REJECT',
        'DOMAIN-KEYWORD,adwords,REJECT', 'DOMAIN-KEYWORD,adservice,REJECT', 'DOMAIN-SUFFIX,appsflyer.com,REJECT', 'DOMAIN-KEYWORD,domob,REJECT', 'DOMAIN-SUFFIX,doubleclick.net,REJECT',
        'DOMAIN-KEYWORD,duomeng,REJECT', 'DOMAIN-KEYWORD,dwtrack,REJECT', 'DOMAIN-KEYWORD,guanggao,REJECT', 'DOMAIN-KEYWORD,lianmeng,REJECT', 'DOMAIN-SUFFIX,mmstat.com,REJECT',
        'DOMAIN-KEYWORD,mopub,REJECT', 'DOMAIN-KEYWORD,omgmta,REJECT', 'DOMAIN-KEYWORD,openx,REJECT', 'DOMAIN-KEYWORD,partnerad,REJECT', 'DOMAIN-KEYWORD,pingfore,REJECT',
        'DOMAIN-KEYWORD,supersonicads,REJECT', 'DOMAIN-KEYWORD,uedas,REJECT', 'DOMAIN-KEYWORD,umeng,REJECT', 'DOMAIN-KEYWORD,usage,REJECT', 'DOMAIN-SUFFIX,vungle.com,REJECT',
        'DOMAIN-KEYWORD,wlmonitor,REJECT', 'DOMAIN-KEYWORD,zjtoolbar,REJECT', 'DOMAIN-SUFFIX,9to5mac.com,⭕ proxinode', 'DOMAIN-SUFFIX,abpchina.org,⭕ proxinode',
        'DOMAIN-SUFFIX,adblockplus.org,⭕ proxinode', 'DOMAIN-SUFFIX,adobe.com,⭕ proxinode', 'DOMAIN-SUFFIX,akamaized.net,⭕ proxinode', 'DOMAIN-SUFFIX,alfredapp.com,⭕ proxinode',
        'DOMAIN-SUFFIX,amplitude.com,⭕ proxinode', 'DOMAIN-SUFFIX,ampproject.org,⭕ proxinode', 'DOMAIN-SUFFIX,android.com,⭕ proxinode', 'DOMAIN-SUFFIX,angularjs.org,⭕ proxinode',
        'DOMAIN-SUFFIX,aolcdn.com,⭕ proxinode', 'DOMAIN-SUFFIX,apkpure.com,⭕ proxinode', 'DOMAIN-SUFFIX,appledaily.com,⭕ proxinode', 'DOMAIN-SUFFIX,appshopper.com,⭕ proxinode',
        'DOMAIN-SUFFIX,appspot.com,⭕ proxinode', 'DOMAIN-SUFFIX,arcgis.com,⭕ proxinode', 'DOMAIN-SUFFIX,archive.org,⭕ proxinode', 'DOMAIN-SUFFIX,armorgames.com,⭕ proxinode',
        'DOMAIN-SUFFIX,aspnetcdn.com,⭕ proxinode', 'DOMAIN-SUFFIX,att.com,⭕ proxinode', 'DOMAIN-SUFFIX,awsstatic.com,⭕ proxinode', 'DOMAIN-SUFFIX,azureedge.net,⭕ proxinode',
        'DOMAIN-SUFFIX,azurewebsites.net,⭕ proxinode', 'DOMAIN-SUFFIX,bing.com,⭕ proxinode', 'DOMAIN-SUFFIX,bintray.com,⭕ proxinode', 'DOMAIN-SUFFIX,bit.com,⭕ proxinode',
        'DOMAIN-SUFFIX,bit.ly,⭕ proxinode', 'DOMAIN-SUFFIX,bitbucket.org,⭕ proxinode', 'DOMAIN-SUFFIX,bjango.com,⭕ proxinode', 'DOMAIN-SUFFIX,bkrtx.com,⭕ proxinode',
        'DOMAIN-SUFFIX,blog.com,⭕ proxinode', 'DOMAIN-SUFFIX,blogcdn.com,⭕ proxinode', 'DOMAIN-SUFFIX,blogger.com,⭕ proxinode', 'DOMAIN-SUFFIX,blogsmithmedia.com,⭕ proxinode',
        'DOMAIN-SUFFIX,blogspot.com,⭕ proxinode', 'DOMAIN-SUFFIX,blogspot.hk,⭕ proxinode', 'DOMAIN-SUFFIX,bloomberg.com,⭕ proxinode', 'DOMAIN-SUFFIX,box.com,⭕ proxinode',
        'DOMAIN-SUFFIX,box.net,⭕ proxinode', 'DOMAIN-SUFFIX,cachefly.net,⭕ proxinode', 'DOMAIN-SUFFIX,chromium.org,⭕ proxinode', 'DOMAIN-SUFFIX,cl.ly,⭕ proxinode',
        'DOMAIN-SUFFIX,cloudflare.com,⭕ proxinode', 'DOMAIN-SUFFIX,cloudfront.net,⭕ proxinode', 'DOMAIN-SUFFIX,cloudmagic.com,⭕ proxinode', 'DOMAIN-SUFFIX,cmail19.com,⭕ proxinode',
        'DOMAIN-SUFFIX,cnet.com,⭕ proxinode', 'DOMAIN-SUFFIX,cocoapods.org,⭕ proxinode', 'DOMAIN-SUFFIX,comodoca.com,⭕ proxinode', 'DOMAIN-SUFFIX,crashlytics.com,⭕ proxinode',
        'DOMAIN-SUFFIX,culturedcode.com,⭕ proxinode', 'DOMAIN-SUFFIX,d.pr,⭕ proxinode', 'DOMAIN-SUFFIX,danilo.to,⭕ proxinode', 'DOMAIN-SUFFIX,dayone.me,⭕ proxinode',
        'DOMAIN-SUFFIX,db.tt,⭕ proxinode', 'DOMAIN-SUFFIX,deskconnect.com,⭕ proxinode', 'DOMAIN-SUFFIX,disq.us,⭕ proxinode', 'DOMAIN-SUFFIX,disqus.com,⭕ proxinode',
        'DOMAIN-SUFFIX,disquscdn.com,⭕ proxinode', 'DOMAIN-SUFFIX,dnsimple.com,⭕ proxinode', 'DOMAIN-SUFFIX,docker.com,⭕ proxinode', 'DOMAIN-SUFFIX,dribbble.com,⭕ proxinode',
        'DOMAIN-SUFFIX,droplr.com,⭕ proxinode', 'DOMAIN-SUFFIX,duckduckgo.com,⭕ proxinode', 'DOMAIN-SUFFIX,dueapp.com,⭕ proxinode', 'DOMAIN-SUFFIX,dytt8.net,⭕ proxinode',
        'DOMAIN-SUFFIX,edgecastcdn.net,⭕ proxinode', 'DOMAIN-SUFFIX,edgekey.net,⭕ proxinode', 'DOMAIN-SUFFIX,edgesuite.net,⭕ proxinode', 'DOMAIN-SUFFIX,engadget.com,⭕ proxinode',
        'DOMAIN-SUFFIX,entrust.net,⭕ proxinode', 'DOMAIN-SUFFIX,eurekavpt.com,⭕ proxinode', 'DOMAIN-SUFFIX,evernote.com,⭕ proxinode', 'DOMAIN-SUFFIX,fabric.io,⭕ proxinode',
        'DOMAIN-SUFFIX,fast.com,⭕ proxinode', 'DOMAIN-SUFFIX,fastly.net,⭕ proxinode', 'DOMAIN-SUFFIX,fc2.com,⭕ proxinode', 'DOMAIN-SUFFIX,feedburner.com,⭕ proxinode',
        'DOMAIN-SUFFIX,feedly.com,⭕ proxinode', 'DOMAIN-SUFFIX,feedsportal.com,⭕ proxinode', 'DOMAIN-SUFFIX,fiftythree.com,⭕ proxinode', 'DOMAIN-SUFFIX,firebaseio.com,⭕ proxinode',
        'DOMAIN-SUFFIX,flexibits.com,⭕ proxinode', 'DOMAIN-SUFFIX,flickr.com,⭕ proxinode', 'DOMAIN-SUFFIX,flipboard.com,⭕ proxinode', 'DOMAIN-SUFFIX,g.co,⭕ proxinode',
        'DOMAIN-SUFFIX,gabia.net,⭕ proxinode', 'DOMAIN-SUFFIX,geni.us,⭕ proxinode', 'DOMAIN-SUFFIX,gfx.ms,⭕ proxinode', 'DOMAIN-SUFFIX,ggpht.com,⭕ proxinode',
        'DOMAIN-SUFFIX,ghostnoteapp.com,⭕ proxinode', 'DOMAIN-SUFFIX,git.io,⭕ proxinode', 'DOMAIN-KEYWORD,github,⭕ proxinode', 'DOMAIN-SUFFIX,globalsign.com,⭕ proxinode',
        'DOMAIN-SUFFIX,gmodules.com,⭕ proxinode', 'DOMAIN-SUFFIX,godaddy.com,⭕ proxinode', 'DOMAIN-SUFFIX,golang.org,⭕ proxinode', 'DOMAIN-SUFFIX,gongm.in,⭕ proxinode',
        'DOMAIN-SUFFIX,goo.gl,⭕ proxinode', 'DOMAIN-SUFFIX,goodreaders.com,⭕ proxinode', 'DOMAIN-SUFFIX,goodreads.com,⭕ proxinode', 'DOMAIN-SUFFIX,gravatar.com,⭕ proxinode',
        'DOMAIN-SUFFIX,gstatic.com,⭕ proxinode', 'DOMAIN-SUFFIX,gvt0.com,⭕ proxinode', 'DOMAIN-SUFFIX,hockeyapp.net,⭕ proxinode', 'DOMAIN-SUFFIX,hotmail.com,⭕ proxinode',
        'DOMAIN-SUFFIX,icons8.com,⭕ proxinode', 'DOMAIN-SUFFIX,ifixit.com,⭕ proxinode', 'DOMAIN-SUFFIX,ift.tt,⭕ proxinode', 'DOMAIN-SUFFIX,ifttt.com,⭕ proxinode',
        'DOMAIN-SUFFIX,iherb.com,⭕ proxinode', 'DOMAIN-SUFFIX,imageshack.us,⭕ proxinode', 'DOMAIN-SUFFIX,img.ly,⭕ proxinode', 'DOMAIN-SUFFIX,imgur.com,⭕ proxinode',
        'DOMAIN-SUFFIX,imore.com,⭕ proxinode', 'DOMAIN-SUFFIX,instapaper.com,⭕ proxinode', 'DOMAIN-SUFFIX,ipn.li,⭕ proxinode', 'DOMAIN-SUFFIX,is.gd,⭕ proxinode',
        'DOMAIN-SUFFIX,issuu.com,⭕ proxinode', 'DOMAIN-SUFFIX,itgonglun.com,⭕ proxinode', 'DOMAIN-SUFFIX,itun.es,⭕ proxinode', 'DOMAIN-SUFFIX,ixquick.com,⭕ proxinode',
        'DOMAIN-SUFFIX,j.mp,⭕ proxinode', 'DOMAIN-SUFFIX,js.revsci.net,⭕ proxinode', 'DOMAIN-SUFFIX,jshint.com,⭕ proxinode', 'DOMAIN-SUFFIX,jtvnw.net,⭕ proxinode',
        'DOMAIN-SUFFIX,justgetflux.com,⭕ proxinode', 'DOMAIN-SUFFIX,kat.cr,⭕ proxinode', 'DOMAIN-SUFFIX,klip.me,⭕ proxinode', 'DOMAIN-SUFFIX,libsyn.com,⭕ proxinode',
        'DOMAIN-SUFFIX,linkedin.com,⭕ proxinode', 'DOMAIN-SUFFIX,linode.com,⭕ proxinode', 'DOMAIN-SUFFIX,lithium.com,⭕ proxinode', 'DOMAIN-SUFFIX,littlehj.com,⭕ proxinode',
        'DOMAIN-SUFFIX,live.com,⭕ proxinode', 'DOMAIN-SUFFIX,live.net,⭕ proxinode', 'DOMAIN-SUFFIX,livefilestore.com,⭕ proxinode', 'DOMAIN-SUFFIX,llnwd.net,⭕ proxinode',
        'DOMAIN-SUFFIX,macid.co,⭕ proxinode', 'DOMAIN-SUFFIX,macromedia.com,⭕ proxinode', 'DOMAIN-SUFFIX,macrumors.com,⭕ proxinode', 'DOMAIN-SUFFIX,mashable.com,⭕ proxinode',
        'DOMAIN-SUFFIX,mathjax.org,⭕ proxinode', 'DOMAIN-SUFFIX,medium.com,⭕ proxinode', 'DOMAIN-SUFFIX,mega.co.nz,⭕ proxinode', 'DOMAIN-SUFFIX,mega.nz,⭕ proxinode',
        'DOMAIN-SUFFIX,megaupload.com,⭕ proxinode', 'DOMAIN-SUFFIX,microsofttranslator.com,⭕ proxinode', 'DOMAIN-SUFFIX,mindnode.com,⭕ proxinode', 'DOMAIN-SUFFIX,mobile01.com,⭕ proxinode',
        'DOMAIN-SUFFIX,modmyi.com,⭕ proxinode', 'DOMAIN-SUFFIX,msedge.net,⭕ proxinode', 'DOMAIN-SUFFIX,myfontastic.com,⭕ proxinode', 'DOMAIN-SUFFIX,name.com,⭕ proxinode',
        'DOMAIN-SUFFIX,nextmedia.com,⭕ proxinode', 'DOMAIN-SUFFIX,nsstatic.net,⭕ proxinode', 'DOMAIN-SUFFIX,nssurge.com,⭕ proxinode', 'DOMAIN-SUFFIX,nyt.com,⭕ proxinode',
        'DOMAIN-SUFFIX,nytimes.com,⭕ proxinode', 'DOMAIN-SUFFIX,omnigroup.com,⭕ proxinode', 'DOMAIN-SUFFIX,onedrive.com,⭕ proxinode', 'DOMAIN-SUFFIX,onenote.com,⭕ proxinode',
        'DOMAIN-SUFFIX,ooyala.com,⭕ proxinode', 'DOMAIN-SUFFIX,openvpn.net,⭕ proxinode', 'DOMAIN-SUFFIX,openwrt.org,⭕ proxinode', 'DOMAIN-SUFFIX,orkut.com,⭕ proxinode',
        'DOMAIN-SUFFIX,osxdaily.com,⭕ proxinode', 'DOMAIN-SUFFIX,outlook.com,⭕ proxinode', 'DOMAIN-SUFFIX,ow.ly,⭕ proxinode', 'DOMAIN-SUFFIX,paddleapi.com,⭕ proxinode',
        'DOMAIN-SUFFIX,parallels.com,⭕ proxinode', 'DOMAIN-SUFFIX,parse.com,⭕ proxinode', 'DOMAIN-SUFFIX,pdfexpert.com,⭕ proxinode', 'DOMAIN-SUFFIX,periscope.tv,⭕ proxinode',
        'DOMAIN-SUFFIX,pinboard.in,⭕ proxinode', 'DOMAIN-SUFFIX,pinterest.com,⭕ proxinode', 'DOMAIN-SUFFIX,pixelmator.com,⭕ proxinode', 'DOMAIN-SUFFIX,pixiv.net,⭕ proxinode',
        'DOMAIN-SUFFIX,playpcesor.com,⭕ proxinode', 'DOMAIN-SUFFIX,playstation.com,⭕ proxinode', 'DOMAIN-SUFFIX,playstation.com.hk,⭕ proxinode',
        'DOMAIN-SUFFIX,playstation.net,⭕ proxinode', 'DOMAIN-SUFFIX,playstationnetwork.com,⭕ proxinode', 'DOMAIN-SUFFIX,pushwoosh.com,⭕ proxinode', 'DOMAIN-SUFFIX,rime.im,⭕ proxinode',
        'DOMAIN-SUFFIX,servebom.com,⭕ proxinode', 'DOMAIN-SUFFIX,sfx.ms,⭕ proxinode', 'DOMAIN-SUFFIX,shadowsocks.org,⭕ proxinode', 'DOMAIN-SUFFIX,sharethis.com,⭕ proxinode',
        'DOMAIN-SUFFIX,shazam.com,⭕ proxinode', 'DOMAIN-SUFFIX,skype.com,⭕ proxinode', 'DOMAIN-SUFFIX,smartdns⭕ proxinode.com,⭕ proxinode', 'DOMAIN-SUFFIX,smartmailcloud.com,⭕ proxinode',
        'DOMAIN-SUFFIX,sndcdn.com,⭕ proxinode', 'DOMAIN-SUFFIX,sony.com,⭕ proxinode', 'DOMAIN-SUFFIX,soundcloud.com,⭕ proxinode', 'DOMAIN-SUFFIX,sourceforge.net,⭕ proxinode',
        'DOMAIN-SUFFIX,spotify.com,⭕ proxinode', 'DOMAIN-SUFFIX,squarespace.com,⭕ proxinode', 'DOMAIN-SUFFIX,sstatic.net,⭕ proxinode', 'DOMAIN-SUFFIX,st.luluku.pw,⭕ proxinode',
        'DOMAIN-SUFFIX,stackoverflow.com,⭕ proxinode', 'DOMAIN-SUFFIX,startpage.com,⭕ proxinode', 'DOMAIN-SUFFIX,staticflickr.com,⭕ proxinode',
        'DOMAIN-SUFFIX,steamcommunity.com,⭕ proxinode', 'DOMAIN-SUFFIX,symauth.com,⭕ proxinode', 'DOMAIN-SUFFIX,symcb.com,⭕ proxinode', 'DOMAIN-SUFFIX,symcd.com,⭕ proxinode',
        'DOMAIN-SUFFIX,tapbots.com,⭕ proxinode', 'DOMAIN-SUFFIX,tapbots.net,⭕ proxinode', 'DOMAIN-SUFFIX,tdesktop.com,⭕ proxinode', 'DOMAIN-SUFFIX,techcrunch.com,⭕ proxinode',
        'DOMAIN-SUFFIX,techsmith.com,⭕ proxinode', 'DOMAIN-SUFFIX,thepiratebay.org,⭕ proxinode', 'DOMAIN-SUFFIX,theverge.com,⭕ proxinode', 'DOMAIN-SUFFIX,time.com,⭕ proxinode',
        'DOMAIN-SUFFIX,timeinc.net,⭕ proxinode', 'DOMAIN-SUFFIX,tiny.cc,⭕ proxinode', 'DOMAIN-SUFFIX,tinypic.com,⭕ proxinode', 'DOMAIN-SUFFIX,tmblr.co,⭕ proxinode',
        'DOMAIN-SUFFIX,todoist.com,⭕ proxinode', 'DOMAIN-SUFFIX,trello.com,⭕ proxinode', 'DOMAIN-SUFFIX,trustasiassl.com,⭕ proxinode', 'DOMAIN-SUFFIX,tumblr.co,⭕ proxinode',
        'DOMAIN-SUFFIX,tumblr.com,⭕ proxinode', 'DOMAIN-SUFFIX,tweetdeck.com,⭕ proxinode', 'DOMAIN-SUFFIX,tweetmarker.net,⭕ proxinode', 'DOMAIN-SUFFIX,twitch.tv,⭕ proxinode',
        'DOMAIN-SUFFIX,txmblr.com,⭕ proxinode', 'DOMAIN-SUFFIX,typekit.net,⭕ proxinode', 'DOMAIN-SUFFIX,ubertags.com,⭕ proxinode', 'DOMAIN-SUFFIX,ublock.org,⭕ proxinode',
        'DOMAIN-SUFFIX,ubnt.com,⭕ proxinode', 'DOMAIN-SUFFIX,ulyssesapp.com,⭕ proxinode', 'DOMAIN-SUFFIX,urchin.com,⭕ proxinode', 'DOMAIN-SUFFIX,usertrust.com,⭕ proxinode',
        'DOMAIN-SUFFIX,v.gd,⭕ proxinode', 'DOMAIN-SUFFIX,v2ex.com,⭕ proxinode', 'DOMAIN-SUFFIX,vimeo.com,⭕ proxinode', 'DOMAIN-SUFFIX,vimeocdn.com,⭕ proxinode',
        'DOMAIN-SUFFIX,vine.co,⭕ proxinode', 'DOMAIN-SUFFIX,vivaldi.com,⭕ proxinode', 'DOMAIN-SUFFIX,vox-cdn.com,⭕ proxinode', 'DOMAIN-SUFFIX,vsco.co,⭕ proxinode',
        'DOMAIN-SUFFIX,vultr.com,⭕ proxinode', 'DOMAIN-SUFFIX,w.org,⭕ proxinode', 'DOMAIN-SUFFIX,w3schools.com,⭕ proxinode', 'DOMAIN-SUFFIX,webtype.com,⭕ proxinode',
        'DOMAIN-SUFFIX,wikiwand.com,⭕ proxinode', 'DOMAIN-SUFFIX,wikileaks.org,⭕ proxinode', 'DOMAIN-SUFFIX,wikimedia.org,⭕ proxinode', 'DOMAIN-SUFFIX,wikipedia.com,⭕ proxinode',
        'DOMAIN-SUFFIX,wikipedia.org,⭕ proxinode', 'DOMAIN-SUFFIX,windows.com,⭕ proxinode', 'DOMAIN-SUFFIX,windows.net,⭕ proxinode', 'DOMAIN-SUFFIX,wire.com,⭕ proxinode',
        'DOMAIN-SUFFIX,wordpress.com,⭕ proxinode', 'DOMAIN-SUFFIX,workflowy.com,⭕ proxinode', 'DOMAIN-SUFFIX,wp.com,⭕ proxinode', 'DOMAIN-SUFFIX,wsj.com,⭕ proxinode',
        'DOMAIN-SUFFIX,wsj.net,⭕ proxinode', 'DOMAIN-SUFFIX,xda-developers.com,⭕ proxinode', 'DOMAIN-SUFFIX,xeeno.com,⭕ proxinode', 'DOMAIN-SUFFIX,xiti.com,⭕ proxinode',
        'DOMAIN-SUFFIX,yahoo.com,⭕ proxinode', 'DOMAIN-SUFFIX,yimg.com,⭕ proxinode', 'DOMAIN-SUFFIX,ying.com,⭕ proxinode', 'DOMAIN-SUFFIX,yoyo.org,⭕ proxinode',
        'DOMAIN-SUFFIX,ytimg.com,⭕ proxinode', 'DOMAIN-SUFFIX,telegra.ph,⭕ proxinode', 'DOMAIN-SUFFIX,telegram.org,⭕ proxinode', 'IP-CIDR,91.108.4.0/22,⭕ proxinode',
        'IP-CIDR,91.108.8.0/21,⭕ proxinode', 'IP-CIDR,91.108.16.0/22,⭕ proxinode', 'IP-CIDR,91.108.56.0/22,⭕ proxinode', 'IP-CIDR,149.154.160.0/20,⭕ proxinode',
        'IP-CIDR6,2001:67c:4e8::/48,⭕ proxinode', 'IP-CIDR6,2001:b28:f23d::/48,⭕ proxinode', 'IP-CIDR6,2001:b28:f23f::/48,⭕ proxinode', 'DOMAIN,injections.adguard.org,DIRECT',
        'DOMAIN,local.adguard.org,DIRECT', 'DOMAIN-SUFFIX,local,DIRECT', 'IP-CIDR,127.0.0.0/8,DIRECT', 'IP-CIDR,172.16.0.0/12,DIRECT', 'IP-CIDR,192.168.0.0/16,DIRECT',
        'IP-CIDR,10.0.0.0/8,DIRECT', 'IP-CIDR,17.0.0.0/8,DIRECT', 'IP-CIDR,100.64.0.0/10,DIRECT', 'IP-CIDR,224.0.0.0/4,DIRECT', 'IP-CIDR6,fe80::/10,DIRECT',
        'IP-CIDR,2002::/16,DIRECT', 'IP-CIDR,2001:db8::/32,DIRECT', 'IP-CIDR,2001::/32,DIRECT', 'IP-CIDR,2001:20::/28,DIRECT', 'GEOIP,CN,DIRECT', 'MATCH,⭕ proxinode'
    ]
    
    with open(OUTPUT_CLASH_FILE, 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
    print(f"成功生成 Clash 订阅文件: {OUTPUT_CLASH_FILE}")

    with open(UPDATE_TIME_FILE, 'w', encoding='utf-8') as f:
        update_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        f.write(f"最后更新时间: {update_time}\n")
        f.write(f"可用节点数量: {len(fast_nodes)}\n")
    print(f"成功记录时间: {UPDATE_TIME_FILE}")

if __name__ == '__main__':
    main()
