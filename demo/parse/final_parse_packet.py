import pandas as pd
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

"""
解析pcap文件，过滤无关报文，提取感兴趣的报文信息，并存储到CSV文件
"""

mac_path = r"../file/feature/Device_MAC.csv"
mac_df = pd.read_csv(mac_path)
mac_set = set()
length_set = {}

# 以字典形式存储相关的报文信息
def udpOutPut(packet, outPut):

    # outPut['num'] = i+1
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
        mac_device = mac_df['MAC'].to_list()
        if packet[Ether].src in mac_device:
            index = mac_device.index(packet[Ether].src)
            outPut['device'] = mac_df.loc[index, 'Device']
            outPut['datalength'] = len(packet[Raw].load) * 10 + 0  # 32是心跳报文，0是无效报文
        else:
            index = mac_device.index(packet[Ether].dst)
            outPut['device'] = mac_df.loc[index, 'Device']
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
        # if (outPut['sport'] == 443) | (outPut['dport'] == 443):
        #     outPut['datalength'] = len(packet[Raw].load) # 关注TCP长度(只比Application Data多5，但特征只需统一即可)
        # # elif (outPut['sport'] == 80) | (outPut['dport'] == 80):
        # #     outPut['datalength'] = len(packet[Raw].load)  # pf[i][Raw].wirelen = None
        # else:outPut['datalength'] = len(packet[Raw].load)
        mac_device = mac_df['MAC'].to_list()
        # try/except部分根据源/目的MAC添加device_name，同时也对数据包长度特征进行更新
        if packet[Ether].src in mac_device:
            index = mac_device.index(packet[Ether].src)
            outPut['device'] = mac_df.loc[index, 'Device']
            outPut['datalength'] = len(packet[Raw].load) * 10 + 0  # 32是心跳报文，0是无效报文
        else:
            index = mac_device.index(packet[Ether].dst)
            outPut['device'] = mac_df.loc[index, 'Device']
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
    mac_device = mac_df['MAC'].to_list()

    # packet_datas = rdpcap(file)
    for i in range(len(packet_datas)):
        # print(pcapFile[i].summary())  # 可直接解析出pcap文件每条报文的summary
        outPut = {}  # {time, proto, src_mac, dst_mac, src_ip, sport, dst_ip, dport,	seq, ack, device, datalength}
        # s = repr(pcapFile[i]) # 同summary，但是更详细，通过它确定包含信息对应的格式，进而在*OutPut中提取
        # print(s)

        # 例：（以下是一个UDP协议报文的解析）
        # <Ether  dst=7c:49:eb:2a:84:04 src=e0:45:6d:64:07:9a type=0x800 |
        # <IP  version=4 ihl=5 tos=0x0 len=60 id=59602 flags=DF frag=0 ttl=49 proto=udp
        # chksum=0x4b46 src=39.156.44.19 dst=192.168.1.65 |
        # <UDP  sport=8053 dport=54321 len=40 chksum=0xb757 |
        # <Raw  load='!1\x00 \x00\x00\x00\x00\x05G\xae\xb3^9*tT\x1a\xd1,d\xca9\xf1c\xc5uQ\xfe\xa1ER' |>>>>

        # 同一个pcap文件包含各种报文，这里只关心有特殊标识的几种协议

        if 'UDP' in packet_datas[i]:  # 解析UDP的报文（网络分层，特殊的协议会有特殊的标识）
            # MDNS，DNS过滤广播；Ether.dst过滤DHCP，DTLS；UDP.dport ==1900 过滤SSDP;
            #
            # UDP.dport == 9898 xiaomi_monkeycom, 该数据包没有加密其实可直接解码获取多功能网关及ZigBee设备行为信息，
            # 解析规则见parse_gateway.py
            #
            # if ('MDNS' in packet_datas[i]) or ('DNS' in packet_datas[i]) or \
            #         (packet_datas[i][Ether].dst == 'ff:ff:ff:ff:ff:ff') or (packet_datas[i][UDP].dport == 1900) or \
            #         ('NBNSQueryRequest' in packet_datas[i]) or \
            #         ('IPv6' in packet_datas[i]) or ('ICMP' in packet_datas[i]) or ('Raw' not in packet_datas[i]) or\
            #         (packet_datas[i][Ether].src not in mac_device and packet_datas[i][Ether].dst not in mac_device) or \
            #         (packet_datas[i][UDP].dport != 9898 and 'Raw' in packet_datas[i] and packet_datas[i][Raw].load in udp_raw):
            #     continue

            if (packet_datas[i][Ether].src not in mac_device and packet_datas[i][Ether].dst not in mac_device) :
                continue
            else:
                if len(udp_raw) > 20:
                    udp_raw.pop(0)
                udpOutPut(packet_datas[i], outPut)  # 对udp格式的报文进一步解析输出
                if len(outPut) > 0:
                    udp_raw.append(packet_datas[i][Raw].load)
                # udp_raw.append(packet_datas[i][Raw].load)
        elif 'TCP' in packet_datas[i]:
            # 22端口ssh；ICMP，IPv6过滤；
            if packet_datas[i][TCP].flags == 17:  # Fin,Ack释放连接，结束会话，则清空tcp_seq队列
                tcp_seq.clear()

            # if (packet_datas[i][TCP].sport == 22) or (packet_datas[i][TCP].dport == 22) or \
            #         ('IPv6' in packet_datas[i]) or ('ICMP' in packet_datas[i])\
            #         (packet_datas[i].haslayer('Ether') and (packet_datas[i][Ether].src not in mac_device and packet_datas[i][Ether].dst not in mac_device)) or \
            #         (packet_datas[i][TCP].seq in tcp_seq):
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
        # if len(outPut) == 0 or (
        #         outPut['src_mac'] in length_set and outPut['datalength'] not in length_set[outPut['src_mac']]) or \
        #         (outPut['dst_mac'] in length_set and outPut['datalength'] not in length_set[outPut['dst_mac']]):
        #     continue

        if len(outPut) == 0:
            continue
        outPutSummary.append(outPut)

    # print("解析有效报文数：", len(outPutSummary), "解析总报文数：", len(packet_datas))  # 输出该file文件的解析报文总数及有效报文总数
    # print(outPutSummary, len(outPutSummary))
    return outPutSummary  # dict, list作为参数传递可修改，无须return


if __name__ == "__main__":
    # pcap_path = r"../file/packets/yeelight_led_blub_1/brightness change"
    pcap_path = "../file/packets"
    packet_path = "wemo_switch/test_dataset/mobile switch onoff/"
    parse_pcap = r"..\file\parse_pcap"

    pcap_path = os.path.join(pcap_path,packet_path)
    # 循环读取该文件夹下所有文件
    for i, j, k in os.walk(pcap_path):
        outPutSummary = []
        # print(i)              #当前文件夹
        # print("/////",j)      #当前文件夹下的文件夹
        # print("***",k)        #当前文件夹下的文件
        # print('\n')
        if len(k) != 0:
            for a in range(len(k)):
                tcp_seq = []
                udp_raw = []
                if k[a].endswith('.pcapng'):
                    file_path = os.path.join(i, k[a])
                    # print(file_path)
                    macset_length = len(mac_set)
                    packet_datas = rdpcap(file_path)

                    parse(packet_datas, outPutSummary, tcp_seq, udp_raw)  # 解析数据包

                    # 导出CSV解析数据包文件
                    df = pd.DataFrame(outPutSummary)
                    df.to_csv(os.path.join(pcap_path, os.path.splitext(k[a])[0]+ '.csv'), index=0, encoding='utf_8_sig')
                    print(file_path, "有效报文数：", len(outPutSummary), "总报文数：",
                          len(packet_datas))  # 输出该file文件的解析报文总数及有效报文总数
                    if len(mac_set) > macset_length:
                        print('*************' + file_path + '*************')  # MAC集增加新MAC，提示该新设备的所处文件
                        print(mac_set)
                    outPutSummary.clear()



