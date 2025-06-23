import requests
import os
from scapy.all import *

from scapy.layers.http import HTTP, HTTPResponse, HTTPRequest
from scapy.layers.inet import TCP


def get_content_type(packet1):
    content_type = (packet1)[HTTPResponse].fields['Content_Type'].decode('utf-8')
    if content_type is not None:
        content_type1 = content_type.split(';')
        content_type2 = content_type1[0].split('/')
        content_type3 = content_type1[1].split('=') if len(content_type1) > 1 else None
        return content_type2[0], content_type2[1], content_type3[1] if content_type3 is not None else None
    else:
        return None, None, None

# 这是一个面相过程的示例
# 定义一个连接
url = os.getenv('IKUAI_URL')

# 使用接口 /Action/login 登录ikuai
# 定义一个登录函数
login_action = '/Action/login'
login_data = {"username": os.getenv('IKUAI_USERNAME'), "passwd": os.getenv('IKUAI_PASSWD'), "pass": os.getenv('IKUAI_PASS'),
              "remember_password": "true"}
# 以raw方式发送请求
r = requests.post(url + login_action, json=login_data)
# 打印返回的结果
cookie = r.cookies.get_dict().get('sess_key')
# 公共方法
call_action = '/Action/call'

# 获取首页信息
# {"func_name":"homepage","action":"show","param":{"TYPE":"sysstat,ac_status"}}
r = requests.post(url + call_action,
                  json={"func_name": "homepage", "action": "show", "param": {"TYPE": "sysstat,ac_status"}},
                  cookies={'sess_key': cookie})
# {"Result":30000,"ErrMsg":"Success","Data":{"sysstat":{"cpu":["0.00%","0.99%","0.00%","0.00%","0.00%"],"cputemp":[],"freq":["1804","1804","1804","1804"],"gwid":"e1b7c6b27d1f4ea38b2cb0e00dd0012a","hostname":"iKuai","link_status":0,"memory":{"total":1902308,"available":1353096,"free":1292744,"cached":66304,"buffers":40008,"used":"28%"},"online_user":{"count":8,"count_2g":0,"count_5g":0,"count_wired":8,"count_wireless":0},"stream":{"connect_num":39,"upload":5920,"download":1624,"total_up":7304699766,"total_down":62898117783},"uptime":423444,"verinfo":{"modelname":"","verstring":"3.7.1 x64 Build202304060952","version":"3.7.1","build_date":202304060952,"arch":"x86","sysbit":"x64","verflags":"","is_enterprise":0,"support_i18n":0,"support_lcd":0}},"ac_status":{"ap_count":0,"ap_online":0}}}
# 获取抓包状态
# {"func_name":"tcpdump","action":"show","param":{"TYPE":"interface,partname,data,status"}}
r = requests.post(url + call_action,
                  json={"func_name": "tcpdump", "action": "show",
                        "param": {"TYPE": "interface,partname,data,status"}},
                  cookies={'sess_key': cookie})
# {"Result":30000,"ErrMsg":"Success","Data":{"interface":[["lan1"],["wan1"],["wan2"]],"partname":[],"data":[{"interface":"","mac":"","hit_num":"100","proto":"","ip_addr":"","port":"","filename":"","size":"0","last_time":""}],"status":0}}
# status 1表示正在抓包，0表示没有抓包
is_tcpdump = r.json().get('Data').get('status')
print(is_tcpdump)
# 如果正在抓包，停止抓包
if is_tcpdump == 1:
    # {"func_name":"tcpdump","action":"stop","param":{}}
    r = requests.post(url + call_action,
                      json={"func_name": "tcpdump", "action": "stop",
                            "param": {}},
                      cookies={'sess_key': cookie})
    print(r.text)
# 开始抓包
# {"func_name":"tcpdump","action":"start","param":{"interface":"wan2","mac":"","hit_num":"80000","proto":"","ip_addr":"","port":"","filename":"","size":0,"last_time":"1681374658"}}
# last_time 为时间戳，可以通过time.time()获取
r = requests.post(url + call_action,
                  json={"func_name": "tcpdump", "action": "start",
                        "param": {"interface": "wan2", "mac": "", "hit_num": "80000", "proto": "", "ip_addr": "",
                                  "port": "", "filename": "", "size": 0, "last_time": scapy.all.time.time()}},
                  cookies={'sess_key': cookie})
print(r.text)
# 通过一些手段打开机顶盒
# TCP 链接
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# 建立连接:
# 使用代理 127.0.0.1 1080
s.connect((os.getenv('SWITCH_IP'), 8080))
# 发送数据: 16进制
s.send(bytes.fromhex('A00101A2'))
# 等待一段时间 暂定 30S
time.sleep(30)
# 停止抓包
# {"func_name":"tcpdump","action":"stop","param":{}}
r = requests.post(url + call_action,
                  json={"func_name": "tcpdump", "action": "stop",
                        "param": {}},
                  cookies={'sess_key': cookie})
print(r.text)
# 获取抓包结果
# https://ikuai.home.linshuboy.cn:40443/pcap/tcpdump.pcap
# 通过上面的链接下载文件到临时文件
# 获取一个临时文件
temp_file = tempfile.NamedTemporaryFile(delete=False)
r = requests.get(url + '/pcap/tcpdump.pcap', cookies={'sess_key': cookie}, stream=True)
# 保存到临时文件
for chunk in r.iter_content(chunk_size=1024):
    if chunk:
        temp_file.write(chunk)
temp_file.close()
# 读取临时文件
packets = sniff(offline=temp_file.name, session=TCPSession)
# packets = sniff(offline='tcpdump.pcap', session=TCPSession)
channel_info = ''
for packet in packets:
    if packet.haslayer(TCP):
        if packet.haslayer(HTTP):
            if packet.haslayer(HTTPRequest):
                pass
            if packet.haslayer(HTTPResponse):
                str1 = packet.load
                a, b, c = get_content_type(packet)
                if a != 'image':
                    content = ''
                    try:
                        content = str1.decode('utf-8' if c is None else c)
                    except:
                        try:
                            content = str1.decode('iso-8859-1')
                        except:
                            pass
                    if 'CCTV1' in content:
                        print(content)
                        if 'CCTV2' in content:
                            if 'CCTV3' in content:
                                if 'CCTV4' in content:
                                    channel_info = content
                                    print(channel_info)
                                    break
ChannelIDs = re.findall(r'[,\']ChannelID="([^"]*)"', channel_info)
ChannelNames = re.findall(r'[,\']ChannelName="([^"]*)"', channel_info)
ChannelURLs = re.findall(r'[,\']ChannelURL="([^"]*)"', channel_info)
TimeShiftURLs = re.findall(r'[,\']TimeShiftURL="([^"]*)"', channel_info)
# 删除临时文件
os.remove(temp_file.name)
# 判断 ChannelIDs 的长度是否等于0 表示没有找到
if len(ChannelIDs) == 0:
    print('未找到ChannelIDs')
else:
    # 输出并写入文件
    m3u_file = open('tv.m3u', 'w', encoding='utf-8')
    m3u_file.write('#EXTM3U\n')
    print(ChannelIDs,1)
    # 高清两个字在ChannelNames[i]中
    CustomChannelOrder = [
        'CCTV1高清',
        'CCTV2高清',
        'CCTV3高清',
        'CCTV4高清',
        'CCTV5高清',
        'CCTV6高清',
        'CCTV7高清',
        'CCTV8高清',
        'CCTV9高清',
        'CCTV10高清',
        'CCTV11高清',
        'CCTV12高清',
        'CCTV13高清',
        'CCTV15高清',
        'CCTV17农业高清',
        'CCTV少儿高清'
    ]
    for name in CustomChannelOrder:
        for i in range(len(ChannelIDs)):
            if ChannelNames[i] == name:
                m3u_file.write('#EXTINF:-1,' + ChannelNames[i] + '\n')
                m3u_file.write(os.getenv('UDP_URL') + ChannelURLs[i][7:] + '/\n')
    for i in range(len(ChannelIDs)):
        if ChannelNames[i] in CustomChannelOrder:
            continue
        if '高清' not in ChannelNames[i]:
            continue
        m3u_file.write('#EXTINF:-1,' + ChannelNames[i] + '\n')
        m3u_file.write(os.getenv('UDP_URL') + ChannelURLs[i][7:] + '/\n')
    for i in range(len(ChannelIDs)):
        if ChannelNames[i] in CustomChannelOrder:
            continue
        if '高清' in ChannelNames[i]:
            continue
        m3u_file.write('#EXTINF:-1,' + ChannelNames[i] + '\n')
        m3u_file.write(os.getenv('UDP_URL') + ChannelURLs[i][7:] + '/\n')
    m3u_file.close()
    # 获取TimeShiftURLs里面的ip地址放到分组里面
    ips = []
    for i in range(len(ChannelIDs)):
        TimeShiftURL = TimeShiftURLs[i]
        print(ChannelNames[i] + ':' + TimeShiftURL)
        ipss = re.findall(r'rtsp://([^:]*):', TimeShiftURL)
        if len(ipss) == 0:
            continue
        ip = ipss[0]
        print(ip)
        if ip not in ips:
            ips.append(ip)
    print(ips,2)
    # 获取iptv_rtsp分组信息
    # {"func_name":"ipgroup","action":"show","param":{"TYPE":"total,data","limit":"0,20","ORDER_BY":"","ORDER":""}}
    r = requests.post(url + call_action,
                      json={"func_name": "ipgroup", "action": "show",
                            "param": {"TYPE": "total,data", "limit": "0,20", "ORDER_BY": "", "ORDER": ""}},
                      cookies={'sess_key': cookie})
    print(r.json())

    ip_groups = r.json().get('Data').get('data')
    iptv_rtsp_group = None
    for ipgroup in ip_groups:
        if ipgroup['group_name'] == 'iptv_rtsp':
            iptv_rtsp_group = ipgroup
            break
    if iptv_rtsp_group is None:
        ip_str = ','.join(ips)
        # 添加分组 {"func_name":"ipgroup","action":"add","param":{"group_name":"iptv_rtsp","addr_pool":"8.8.8.8","type":0,"newRow":true,"comment":""}}
        r = requests.post(url + call_action,
                          json={"func_name": "ipgroup", "action": "add",
                                "param": {"group_name": "iptv_rtsp", "addr_pool": ip_str, "type": 0,
                                          "comment": ""}},
                          cookies={'sess_key': cookie})
        print(r.json())
    else:
        old_ips = iptv_rtsp_group['addr_pool'].split(',')
        # 将ips中的ip添加到old_ips中
        for ip in ips:
            if ip in old_ips:
                old_ips.remove(ip)
            old_ips.append(ip)
        # 如果old_ips中的ip数量大于5，删除最早的ip
        if len(old_ips) > 5:
            old_ips = old_ips[len(old_ips) - 5:]
        ip_str = ','.join(old_ips)
        # 更新 {"func_name":"ipgroup","action":"edit","param":{"id":1,"group_name":"iptv_rtsp","addr_pool":"8.8.8.7","type":0,"comment":""}}
        r = requests.post(url + call_action,
                          json={"func_name": "ipgroup", "action": "edit",
                                "param": {"id": iptv_rtsp_group['id'], "group_name": "iptv_rtsp",
                                          "addr_pool": ip_str,
                                          "type": 0, "comment": ""}},
                          cookies={'sess_key': cookie})
        print(r.json())
time.sleep((os.getenv('SLEEP_TIME', '300')))
print('关闭机顶盒')
# 通过一些手段关闭机顶盒
# 发送数据: 16进制
s.send(bytes.fromhex('A00100A1'))
s.close()
