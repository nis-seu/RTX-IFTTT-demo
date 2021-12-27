# -!- coding: utf-8 -!-
import demo.util.deal_csv as dl
from scapy.all import *
import demo.parse.final_parse_packet as parser
import demo.recognition.test_recognition as recognizer

device_mac_path = r"../file/feature/Device_MAC.csv"
# device_mac_path = "/root/upload/demo/file/feature/Device_MAC.csv"
netword_card = 'br-lan'
max_length = {
    'Yeelight_LED_Bulb_1': 4,
    'wemo_switch': 4,
}
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
    # 开始抓取
    dump_packets.start()
    time.sleep(2)
    while True:
        # try:
            dump_packets.stop()
            stop_time = datetime.now()
            # 获取包
            dump_packet = dump_packets.results
            dump_packets.start()
            time.sleep(2)
            # 解析包
            out_put,tcp_seq,udp_raw = [], [], []
            parser.parse(dump_packet, out_put, tcp_seq, udp_raw)

            # 如果本次抓到有效包，
            if len(out_put) > 0:
                # 识别
                ans = recognizer.recognize(out_put)
                print(ans)
                for item in ans:
                    recognizer.take_action(item)
