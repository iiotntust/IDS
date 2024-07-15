# from scapy.all import *
# import threading
# from flask import Flask

# app = Flask(__name__)

# # 定義全域變數
# INTERFACE = '乙太網路'  # 監聽介面
# THRESHOLD_DDOS = 500  # 封包計數的閾值
# THRESHOLD_MITM = 100  # ARP 請求計數的閾值
# INTERVAL = 5  # 檢查計數的間隔時間（秒）
# whitelist = set(['192.168.40.14', '192.168.40.15'])  # 白名單，允許的 IP 地址列表

# # 定義偵測函式
# def detect_attacks():
#     #print("Packets detected1")
#     # 如果短時間有大量封包，則認為是 DDoS 攻擊
#     packets = sniff(count=1000, iface=INTERFACE)
#     #print("Packets detected2")
#     ddos_packets = [packet for packet in packets if packet.haslayer('TCP')]
#     print("Packets detected3")
#     packet_contents = [str(packet) for packet in ddos_packets]  # Convert packets to strings

#     ddos_detected =len(packet_contents) > THRESHOLD_DDOS 
#     print(len(packet_contents))
#     arp_packets =  [packet for packet in packets if packet.haslayer('ARP')]   
#     arp_packet_contents = [str(packet) for packet in arp_packets]  # Convert packets to strings

#     mitm_detected = len(arp_packet_contents) > THRESHOLD_MITM
#     print(len(arp_packet_contents))
#     if ddos_detected:
#         print("DDoS attack detected")
#     if mitm_detected:
#         print("MITM attack detected")
#     return ddos_detected, mitm_detected



# def setInterval(func, sec):
#     def func_wrapper():
#         setInterval(func, sec)
#         func()
#     t = threading.Timer(sec, func_wrapper)
#     t.start()
#     return t

# @app.route('/')
# def display_attack():
#     print("Display attack")
#     ddos_detected, mitm_detected = detect_attacks()
#     if ddos_detected:
#         return '<html><head><meta http-equiv="refresh" content="10"><html><body><h1>Attack Detection</h1><p>DDoS attack detected</p></body></html>'
#     if mitm_detected:
#         return '<html><head><meta http-equiv="refresh" content="10"><html><body><h1>Attack Detection</h1><p>MITM attack detected</p></body></html>'
#     return '<html><head><meta http-equiv="refresh" content="10"><html><body><h1>Attack Detection</h1><p>No attack detected</p></body></html>'

# if __name__ == '__main__':
#     setInterval(detect_attacks, INTERVAL)
#     app.run()

# from scapy.all import *
# from flask import Flask

# app = Flask(__name__)

# # 定義全域變數
# INTERFACE = 'Ethernet 3'  # 監聽介面
# THRESHOLD_DDOS = 300 # 封包計數的閾值
# THRESHOLD_MITM = 100  # ARP 請求計數的閾值
# INTERVAL = 10  # 檢查計數的間隔時間（秒）
# WHITELIST = {'192.168.40.14', '192.168.40.15'}  # 白名單,允許的 IP 地址列表

# def detect_attacks(count=1000):
#     packets = sniff(count=count, iface=INTERFACE)#, timeout=INTERVAL)
#     #ddos_packets = sniff(count=count, iface=INTERFACE, timeout=INTERVAL)
#     ddos_packets = [packet for packet in packets if packet.haslayer('TCP')]
#     ddos_detected = len(ddos_packets) > THRESHOLD_DDOS
#     print(len(ddos_packets))
#     arp_packets = [packet for packet in packets if packet.haslayer('ARP')]
#     mitm_detected = len(arp_packets) > THRESHOLD_MITM
#     print(len(arp_packets))
#     return ddos_detected, mitm_detected, ddos_packets, arp_packets

# def is_valid_ip(ip):
#     # 驗證 IP 地址格式
#     # ...
#     return True  # 假設所有 IP 地址都是有效的

# @app.route('/')
# def display_attack():
#     print("Display attack")
#     ddos_detected, mitm_detected, ddos_packets, arp_packets = detect_attacks()

#     for packet in ddos_packets:
#         try:
#             src_ip = packet['IP'].src
#             if not is_valid_ip(src_ip) or src_ip in WHITELIST:
#                 ddos_packets.remove(packet)
#         except:
#             pass

#     for packet in arp_packets:
#         try:
#             src_ip = packet['ARP'].psrc
#             if not is_valid_ip(src_ip) or src_ip in WHITELIST:
#                 arp_packets.remove(packet)
#         except:
#             pass

#     if ddos_detected:
#         return '<html><head><meta http-equiv="refresh" content="10"><html><body><h1>Attack Detection</h1><p>DDoS attack detected</p></body></html>'
#     if mitm_detected:
#         return '<html><head><meta http-equiv="refresh" content="10"><html><body><h1>Attack Detection</h1><p>MITM attack detected</p></body></html>'
#     return '<html><head><meta http-equiv="refresh" content="10"><html><body><h1>Attack Detection</h1><p>No attack detected</p></body></html>'

# if __name__ == '__main__':
#     app.run()

from scapy.all import *
from flask import Flask
import time
from collections import defaultdict

app = Flask(__name__)

# 定義全域變數
INTERFACE = 'Ethernet 3'  
THRESHOLD_DDOS = 750 
THRESHOLD_MITM = 20  
RESET_INTERVAL = 60 * 1 
WHITELIST = {'192.168.40.13','192.168.40.14', '192.168.40.15','192.168.40.20','192.168.40.2','192.168.40.96','192.168.40.126','192.168.40.6'} 

# 計數器和上次攻擊時間
global mitm_detected 
global last_attack_time
global start_time
last_attack_time = 0
start_time =0
mitm_detected = False

# 用於記錄重複的 ARP 請求來源
arp_request_sources = defaultdict(int)


def detect_attacks(count=1000):
    global mitm_detected, last_attack_time 
     
    packets = sniff(count=count, iface=INTERFACE)#, timeout=INTERVAL)
    ddos_packets = [packet for packet in packets if packet.haslayer('TCP')]
    ddos_detected = len(ddos_packets) > THRESHOLD_DDOS
    print(len(ddos_packets))

    udp_packets = [packet for packet in packets if packet.haslayer('UDP')]
    # print(len(udp_packets))

    arp_detected = False
    arp_requests = [packet for packet in packets if packet.haslayer('ARP') and packet.dst == 'ff:ff:ff:ff:ff:ff']#and packet['ARP'].op == 1]
    for packet in arp_requests:
        src_ip = packet['ARP'].psrc
        if arp_request_sources[src_ip] >= THRESHOLD_MITM:
            arp_detected = True
            break
        arp_request_sources[src_ip] += 1

    if arp_detected:
        mitm_detected = arp_request_sources[src_ip] >= THRESHOLD_MITM
        last_attack_time = time.time()
        arp_request_sources.clear()


    print(len(arp_requests))
    print(len(udp_packets))
    print(arp_request_sources)
 

    
    return ddos_detected, mitm_detected, ddos_packets, arp_requests
    

def is_valid_ip(ip):
    # 驗證 IP 地址格式
    # ...
    return True  # 假設所有 IP 地址都是有效的

@app.route('/')
def display_attack():
    global start_time
    ddos_detected, mitm_detected, ddos_packets, arp_packets, = detect_attacks()

    malicious_ips = set()
    for packet in ddos_packets:
        try:
            src_ip = packet['IP'].src
            if not is_valid_ip(src_ip) or src_ip not in WHITELIST:
                malicious_ips.add(src_ip)
        except:
            pass

    for packet in arp_packets:
        try:
            src_ip = packet['ARP'].psrc
            if not is_valid_ip(src_ip) or src_ip not in WHITELIST:
                malicious_ips.add(src_ip)
        except:
            pass

    if time.time() - last_attack_time > RESET_INTERVAL:
        mitm_detected = False
             

    if time.time() - start_time > RESET_INTERVAL:
        start_time = time.time()
        arp_request_sources.clear()
        
    

    if ddos_detected:
        return '<html><head><meta http-equiv="refresh" content="5"><html><body><h1>Attack Detection</h1><p>DDoS attack detected</p></body></html>'
    if mitm_detected:
        return '<html><head><meta http-equiv="refresh" content="5"><html><body><h1>Attack Detection</h1><p>MITM attack detected</p></body></html>'
    if malicious_ips:
        return f'<html><head><meta http-equiv="refresh" content="5"><html><body><h1>Attack Detection</h1><p>Malicious IPs detected: {malicious_ips}</p></body></html>'
    return '<html><head><meta http-equiv="refresh" content="5"><html><body><h1>Attack Detection</h1><p>No attack detected</p></body></html>'

if __name__ == '__main__':
    start_time = time.time()
    app.run()