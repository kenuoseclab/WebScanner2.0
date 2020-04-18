from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.l2 import Ether, ARP
from scapy.all import *
import logging

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)


# ifname: 网卡设备的名字
def arp_request(ip_address, queue=None):
    try:
        ans, uans = srp(Ether(dst="FF:FF:FF:fF:fF:FF") / ARP(pdst=ip_address), timeout=10, verbose=False)
        if len(ans) > 0:
            ip = ans[0][1][1].fields['psrc']
            MAC = ans[0][1][1].fields['hwsrc']
            if queue is None:
                print(ip, ' <<===>> ', MAC, ' is up')
                return ip
            else:
                print(ip, ' <<===>> ', MAC, ' is up')
                queue.put((ip, MAC))
    except Exception as e:
        pass


def ping_one(host, queue=None):
    try:
        ans, uans = sr(IP(dst=host) / ICMP(), timeout=5, verbose=False)
        if len(ans) > 0:
            ip = ans[0][1].fields['src']
            if queue is None:
                print(ip, ' is up')
                return ip
            else:
                print(ip, ' is up')
                queue.put(ip)
    except Exception as e:
        pass


def syn_443(host, queue=None):
    try:
        ans, uans = sr(IP(dst=host)/TCP(dport=443, flags="S"), timeout=5, verbose=False)
        if len(ans) > 0:
            ip = ans[0][1].fields['src']
            if queue is None:
                print(ip, ' is up')
                return ip
            else:
                print(ip, ' is up')
                queue.put(ip)
    except Exception as e:
        pass


def ack_80(host, queue=None):
    """
    如果一个主机存在的话，向它发送一个flags为ACK包的话，无论端口是否关闭都会有返回一个flags为RST包，
    如果是主机不存在的话就会一个数据包都不会返回
    :param host:
    :param queue:
    :return:
    """
    try:
        ans, uans = sr(IP(dst=host) / TCP(dport=80, flags="A"), timeout=5, verbose=False)
        if len(ans) > 0:
            ip = ans[0][1].fields['src']
            if queue is None:
                print(ip, ' is up')
                return ip
            else:
                print(ip, ' is up')
                queue.put(ip)
    except Exception as e:
        pass


if __name__ == '__main__':
    # arp_request("192.168.43.0/24")
    # ping_one("192.168.43.0/24")
    syn_443("192.168.43.224")
    ack_80("192.168.43.224")