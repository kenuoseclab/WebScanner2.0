from scapy.layers.inet import IP, TCP, UDP
from scapy.all import *
from scan.settings import Settings
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def syn_one(hostname, port, queue=None):
    """
    TCP SYN扫描又称半开式扫描，该过程不会和服务端建立完整的连接，
    首先客户端会发送一个带有SYN标识和端口号的TCP数据包给服务器，如果服务器这个端口是开放的，
    则会接受这个连接并返回一个带有SYN和ACK标识的数据包给客户端，
    随后客户端会返回带有RST标识的数据包而不是返回一个带有ACK和RST标识的数据包。从而不会和服务端建立完整的连接
    如果目标端口处于关闭状态，则服务端会返回一个RST标识的数据包。
    :param queue:
    :param port:
    :param hostname:
    :return:
    """
    try:
        ans, uans = sr(IP(dst=hostname) / TCP(dport=port, flags="S"), timeout=1, verbose=False)
        if len(ans) > 0:
            if ans[0][1][1].fields['flags'] == 'SA':
                if queue is None:
                    print("[+] %s %d \033[92m Open \033[0m" % (hostname, port))
                else:
                    print("[+] %s %d \033[92m Open \033[0m" % (hostname, port))
                    queue.put(port)
    except Exception as e:
        pass


def fin_one(hostname, port, queue=None):
    """
    在发送的数据包中只设置FIN标志位，如果目标端口是开放的则不会回复任何信息。
    如果目标端口关闭则会返回一个RST+ACK的数据包
    :param queue:
    :param port:
    :param hostname:
    :return:
    """
    try:
        ans, uans = sr(IP(dst=hostname) / TCP(dport=port, flags="F"), timeout=1, verbose=False)
        if len(ans) == 0:
            if queue is None:
                print("[+] %s  %d \033[91m Open | filtered\033[0m" % (hostname, port))
            else:
                print("[+] %s  %d \033[91m Open | filtered\033[0m" % (hostname, port))
                queue.put(port)
    except Exception as e:
        pass


def null_one(hostname, port, queue=None):
    """
    在发送的数据包中不设置任何标志位(tcp标志头是0)，如果目标端口是开放的则不会回复任何信息。
    如果目标端口关闭则会返回一个RST+ACK的数据包.
    :param queue:
    :param port:
    :param hostname:
    :return:
    """
    try:
        ans, uans = sr(IP(dst=hostname) / TCP(dport=port, flags=""), timeout=1, verbose=False)
        if len(ans) == 0:
            if queue is None:
                print("[+] %s  %d \033[91m Open | filtered\033[0m" % (hostname, port))
            else:
                print("[+] %s  %d \033[91m Open | filtered\033[0m" % (hostname, port))
                queue.put(port)
    except Exception as e:
        pass


def xmas_one(hostname, port, queue=None):
    """
    在发送的数据包中设置PSH,FIN,URG标志位，如果目标端口是开放的则不会回复任何信息。
    如果目标端口关闭则会返回一个RST+ACK的数据包
    :param queue:
    :param port:
    :param hostname:
    :return:
    """
    try:
        ans, uans = sr(IP(dst=hostname) / TCP(dport=port, flags="PFU"), timeout=1, verbose=False)
        if len(ans) == 0:
            if queue is None:
                print("[+] %s  %d \033[91m Open | filtered\033[0m" % (hostname, port))
            else:
                print("[+] %s  %d \033[91m Open | filtered\033[0m" % (hostname, port))
                queue.put(port)
    except Exception as e:
        pass


def udp_one(hostname, port, queue=None):
    """
    UDP端口扫描是通过普通数据包进行的，也是用于扫描对方端口上是否有程序在运行，
    因为它是无连接不可靠的协议，发送数据包过去以后，通常也不会有任何的对等回应。
    因此，UDP端口扫描主要是检测是否存在ICMP端口不可达数据包。若该数据包出现，则说明对方这一端口上没有程序在监听，
    否则就说明该端口上有程序在监听。
    :param hostname:
    :param port:
    :param queue:
    :return:
    """
    try:
        ans, uans = sr(IP(dst=hostname)/UDP(dport=port), timeout=0.08, verbose=False)
        if len(ans) == 0:
            if queue is None:
                print("[+] %s  %d \033[91m Open | filtered\033[0m" % (hostname, port))
            else:
                print("[+] %s  %d \033[91m Open | filtered\033[0m" % (hostname, port))
                queue.put(port)
    except Exception as e:
        pass


if __name__ == '__main__':
    # ip = input("请输入你的ip地址: ")
    # start_port = input("请输入你的开始端口: ")
    # end_port = input("请输入你的结束端口: ")
    # udp_one(ip, start_port, end_port)
    syn_one("192.168.43.0/24", 53)