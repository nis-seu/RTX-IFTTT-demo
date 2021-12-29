# -!- coding: utf-8 -!-
import demo.deal_csv as dl
from scapy.all import *
import demo.final_parse_packet as parser
import demo.test_recognition as recognizer

device_mac_path = r"file/feature/Device_MAC.csv"
# device_mac_path = "/root/upload/demo/file/feature/Device_MAC.csv"
netword_card = 'br-lan'

# set the filter of AsyncSniffer
def get_filter(mac_path):
    mac_df = dl.read_csv(mac_path)
    ma = []
    for item in mac_df:
        if item[0] != 'MAC' :
            ma.append(item[0])

    filter = 'ether host'
    for i in range(len(ma)-1):
        filter += ' '+ma[i]+ ' or'
    filter += ' '+ma[len(ma)-1]
    return filter



if __name__ == "__main__":
    time_record = [] # record time
    dump_packets = AsyncSniffer(iface= netword_card,
                                filter=get_filter(device_mac_path))
    file_index = 0
    dump_packets.start()
    time.sleep(2)
    while True:
        # try:
            dump_packets.stop()
            stop_time = datetime.now()
            dump_packet = dump_packets.results
            dump_packets.start()
            time.sleep(2)
            out_put,tcp_seq,udp_raw = [], [], []
            parser.parse(dump_packet, out_put, tcp_seq, udp_raw)
            if len(out_put) > 0:
                ans = recognizer.recognize(out_put)
                print(ans)
                for item in ans:
                    recognizer.take_action(item)
