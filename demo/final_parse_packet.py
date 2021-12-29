import demo.deal_csv as dl
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether


mac_path = "file/feature/Device_MAC.csv"
# device_mac_path = "/root/upload/demo/file/feature/Device_MAC.csv"
mac_df = dl.read(mac_path)
mac_set = set()
length_set = {}

# Extract information from UDP packets
def udpOutPut(packet, outPut):
    if packet[UDP].dport == 9898:
        tmp = eval(packet[Raw].load.decode())
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
        outPut.clear()
    return outPut

# Extract information from TCP packets
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
    elif 'IPv6' in packet:
        outPut['src_ip'] = packet[IPv6].src
        outPut['sport'] = packet[TCP].sport
        outPut['dst_ip'] = packet[IPv6].dst
        outPut['dport'] = packet[TCP].dport
    outPut['seq'] = packet[TCP].seq
    outPut['ack'] = packet[TCP].ack
    if 'Raw' in packet and len(packet[Raw].load) != 0 and len(packet[Raw].load) != 57:
        mac_device = []
        for item in mac_df:
            if item[0] != 'MAC':
                mac_device.append(item[0])
        if packet[Ether].src in mac_device:
            index = mac_device.index(packet[Ether].src)
            outPut['device'] = mac_df[index+1][1]
            outPut['datalength'] = len(packet[Raw].load) * 10 + 0
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

# Filter packets and extract information
def parse(packet_datas, outPutSummary, tcp_seq: list, udp_raw: list):
    mac_device = []
    for item in mac_df:
        if item[0] != 'MAC':
            mac_device.append(item[0])
    for i in range(len(packet_datas)):
        outPut = {}  # {time, proto, src_mac, dst_mac, src_ip, sport, dst_ip, dport,	seq, ack, device, datalength}
        if 'UDP' in packet_datas[i]:
            if (packet_datas[i][Ether].src not in mac_device and packet_datas[i][Ether].dst not in mac_device) :
                continue
            else:
                if len(udp_raw) > 20:
                    udp_raw.pop(0)
                udpOutPut(packet_datas[i], outPut)
                if len(outPut) > 0:
                    udp_raw.append(packet_datas[i][Raw].load)
        elif 'TCP' in packet_datas[i]:
            if packet_datas[i][TCP].flags == 17:
                tcp_seq.clear()
            if (packet_datas[i][Ether].src not in mac_device and packet_datas[i][Ether].dst not in mac_device) or \
                    (packet_datas[i][TCP].seq in tcp_seq):
                continue
            else:
                if len(tcp_seq) > 10:
                    tcp_seq.pop(0)
                tcpOutPut(packet_datas[i], outPut)
                if len(outPut) > 0:
                    tcp_seq.append(packet_datas[i][TCP].seq)
        elif 'ARP' in packet_datas[i]:
            continue
        if len(outPut) == 0:
            continue
        outPutSummary.append(outPut)
    return outPutSummary



