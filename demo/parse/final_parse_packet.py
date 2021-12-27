import demo.util.deal_csv as dl
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

"""
解析pcap文件，过滤无关报文，提取感兴趣的报文信息，并存储到CSV文件
"""
mac_path = "../file/feature/Device_MAC.csv"
# device_mac_path = "/root/upload/demo/file/feature/Device_MAC.csv"
mac_df = dl.read(mac_path)
mac_set = set()
length_set = {}

# 以字典形式存储相关的报文信息
def udpOutPut(packet, outPut):
    if packet[UDP].dport == 9898:  # 直接剔除非Gateway的心跳报文
        tmp = eval(packet[Raw].load.decode())  # 解码并转字典存储
        if 'heartbeat' == tmp['cmd'] and 'gateway' != tmp['model']:
            return outPut

    outPut['time'] = datetime.fromtimestamp(float(packet.time)).strftime("%Y-%m-%d %H:%M:%S.%f")
    if 'NTPHeader' in packet:
        outPut['proto'] = "NTP"
    else:
        outPut['proto'] = "UDP"
    outPut['src_mac'] = packet[Ether].src
    outPut['dst_mac'] = packet[Ether].dst
    outPut['src_ip'] = packet[IP].src
    outPut['sport'] = packet[UDP].sport
    outPut['dst_ip'] = packet[IP].dst
    outPut['dport'] = packet[UDP].dport
    # outPut['chksum'] = packet[UDP].chksum
    if 'Raw' in packet and len(packet[Raw].load) != 32 and len(packet[Raw].load) != 0:
        mac_device = []
        for item in mac_df:
            if item[0] != 'MAC':
                mac_device.append(item[0])

        if packet[Ether].src in mac_device:
            index = mac_device.index(packet[Ether].src)
            outPut['device'] = mac_df[index+1][1]
            outPut['datalength'] = len(packet[Raw].load) * 10 + 0  # 32是心跳报文，0是无效报文
        else:
            index = mac_device.index(packet[Ether].dst)
            outPut['device'] = mac_df[index+1][1]
            outPut['datalength'] = len(packet[Raw].load) * 10 + 1
        mac_set.add(packet[Ether].src)
        mac_set.add(packet[Ether].dst)
    else:
        # outPut['datalength'] = 0
        outPut.clear()
    return outPut

# 以字典形式存储相关的报文信息
def tcpOutPut(packet,outPut):
    outPut['time'] = datetime.fromtimestamp(float(packet.time)).strftime("%Y-%m-%d %H:%M:%S.%f")
    outPut['proto'] = "TCP"
    outPut['src_mac'] = packet[Ether].src
    outPut['dst_mac'] = packet[Ether].dst
    if 'IP' in packet:
        outPut['src_ip'] = packet[IP].src
        outPut['sport'] = packet[TCP].sport
        outPut['dst_ip'] = packet[IP].dst
        outPut['dport'] = packet[TCP].dport
    elif 'IPv6' in packet:  # IPv6已过滤以下不会涉及（为避免以后设备通信协议升级，留下参考）
        outPut['src_ip'] = packet[IPv6].src
        outPut['sport'] = packet[TCP].sport
        outPut['dst_ip'] = packet[IPv6].dst
        outPut['dport'] = packet[TCP].dport
    outPut['seq'] = packet[TCP].seq  # TCP握手连接根据seq + ack确定数据包顺序及是否重传
    outPut['ack'] = packet[TCP].ack
    # outPut['chksum'] = packet[TCP].chksum
    # outPut['packetlength'] = packet.length
    if 'Raw' in packet and len(packet[Raw].load) != 0 and len(packet[Raw].load) != 57:
        mac_device = []
        for item in mac_df:
            if item[0] != 'MAC':
                mac_device.append(item[0])
        # try/except部分根据源/目的MAC添加device_name，同时也对数据包长度特征进行更新
        if packet[Ether].src in mac_device:
            index = mac_device.index(packet[Ether].src)
            outPut['device'] = mac_df[index+1][1]
            outPut['datalength'] = len(packet[Raw].load) * 10 + 0  # 32是心跳报文，0是无效报文
        else:
            index = mac_device.index(packet[Ether].dst)
            outPut['device'] = mac_df[index+1][1]
            outPut['datalength'] = len(packet[Raw].load) * 10 + 1
        # outPut['datalength'] = len(packet[Raw].load)
        if outPut['device'] == 'Smart_Life_Smart_Strips' and outPut['datalength'] == 2550:
            status_id = int.from_bytes(packet[Raw].load[42:44], byteorder='big', signed=False)
            outPut['datalength'] = outPut['datalength'] * 10 + status_id % 2
        elif outPut['device'] == 'Smart_Life_Smart_Strips' and outPut['datalength'] == 41:
            status_id = int.from_bytes(packet[Raw].load[2:4], byteorder='big', signed=False)
            outPut['datalength'] = outPut['datalength'] * 10 + status_id % 2
        mac_set.add(packet[Ether].src)
        mac_set.add(packet[Ether].dst)
    else:
        outPut.clear()
    return outPut

# 对pcap文件中的每条报文进行过滤及相关解析，获取相应的几条指定信息（sour/dst ip/mac/port len等）
def parse(packet_datas, outPutSummary, tcp_seq: list, udp_raw: list):
    """
    :return:
    :param udp_raw: 过滤udp.Raw数据段相同报文（重播报文）
    :param tcp_seq: 过滤tcp.transmission,
    :param packet_datas: packet_list
    :param length_set: 每个设备单独的行为特征合集{MAC1:(length_set), MAC2:(length_set),...}
    :param mac_set: 处理过的所有文件中所出现的MAC合集,仅做test时检测每个pcap出现哪个设备用，与功能无关
    :param outPutSummary: 对当前pcap文件的处理结果，list
    :param mac_df: 可识别的设备MAC及对应device_name，无关则过滤
    """
    mac_device = []
    for item in mac_df:
        if item[0] != 'MAC':
            mac_device.append(item[0])

    for i in range(len(packet_datas)):
        outPut = {}  # {time, proto, src_mac, dst_mac, src_ip, sport, dst_ip, dport,	seq, ack, device, datalength}
        if 'UDP' in packet_datas[i]:  # 解析UDP的报文（网络分层，特殊的协议会有特殊的标识）
            if (packet_datas[i][Ether].src not in mac_device and packet_datas[i][Ether].dst not in mac_device) :
                continue
            else:
                if len(udp_raw) > 20:
                    udp_raw.pop(0)
                udpOutPut(packet_datas[i], outPut)  # 对udp格式的报文进一步解析输出
                if len(outPut) > 0:
                    udp_raw.append(packet_datas[i][Raw].load)
        elif 'TCP' in packet_datas[i]:
            # 22端口ssh；ICMP，IPv6过滤；
            if packet_datas[i][TCP].flags == 17:  # Fin,Ack释放连接，结束会话，则清空tcp_seq队列
                tcp_seq.clear()
            if (packet_datas[i][Ether].src not in mac_device and packet_datas[i][Ether].dst not in mac_device) or \
                    (packet_datas[i][TCP].seq in tcp_seq):
                continue
            else:
                if len(tcp_seq) > 10:  # 减少tcp.seq占用内存大小，因为重传报文间隔很短
                    tcp_seq.pop(0)
                tcpOutPut(packet_datas[i], outPut)  # 对tcp格式的报文进一步解析输出
                if len(outPut) > 0:
                    tcp_seq.append(packet_datas[i][TCP].seq)
        elif 'ARP' in packet_datas[i]:
            continue
        if len(outPut) == 0:
            continue
        outPutSummary.append(outPut)
    return outPutSummary  # dict, list作为参数传递可修改，无须return



