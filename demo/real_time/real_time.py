# -!- coding: utf-8 -!-
import pandas as pd
from scapy.all import *
import demo.parse.final_parse_packet as parser
import demo.recognition.test_recognition as recognizer

device_mac_path = r"../file/feature/Device_MAC.csv"
csv_path = "../file/real_time/parse_pcap"
netword_card = 'Microsoft Wi-Fi Direct Virtual Adapter #2'
max_length = {
    'Yeelight_LED_Bulb_1': 4,
    'wemo_switch': 5,
}

def get_pre_csv():
    files =os.listdir(csv_path)
    if len(files)>0:
        file = os.path.join(csv_path, files[len(files)-1])
        if os.path.getsize(file):
            return True,pd.read_csv(file)
        else:
            return False, {}
    else:
        return False, {}

def get_filter(mac_path):
    mac_df = pd.read_csv(mac_path)
    ma = mac_df['MAC'].to_list()
    filter = 'ether host'
    for i in range(len(ma)-1):
        filter += ' '+ma[i]+ ' or'
    filter += ' '+ma[len(ma)-1]
    return filter

def get_device_list():
    mac_df = pd.read_csv(device_mac_path)
    de = mac_df['Device'].to_list()
    device_packets = {}
    for item in de:
        device_packets[item] = []
    return device_packets


def delete_all_csv_file():
    files = os.listdir(csv_path)
    for item in files:
        os.remove(os.path.join(csv_path,item))

def save_packet(df,file_index):
    df.to_csv(os.path.join(csv_path, 'packets_' + str(file_index) + '.csv'), index=0, encoding='utf_8_sig')

def combine_packets(is_exist,pre,now):
    if is_exist:
        return pd.concat([pre,now],ignore_index=True),len(pre)
    else:
        return now, 0

def set_Pre_Cut_Index():
    pre_cut_index = {}
    for key in max_length:
        pre_cut_index[key] =0
    return pre_cut_index


def recognize(csv_packets,start_index):

    device_packets = get_device_list()
    # 把pre的包放入device——packets中
    for index in range(0,start_index):
        device_packets[csv_packets.loc[index, 'device']].append(csv_packets.loc[index])
    results = []

    # 设置匹配的终点
    pre_cut_index = set_Pre_Cut_Index()
    # 循环识别流量
    for index in range(start_index,len(csv_packets)):
        # 获取设备名
        device = csv_packets.loc[index, 'device']
        # 把流量加入设备对应的packets
        device_packets[device].append(csv_packets.loc[index])
        # 获取设备对应的features
        features = recognizer.get_features(str(device).lower())
        # 检查当前是否有特征匹配
        for index_features in range(len(features)):
            if is_match(device_packets[device], features[index_features],pre_cut_index[device]):
                result = {}
                result['device'] = device
                result['operation'] = features[index_features]['Operation']
                result['time'] = csv_packets.loc[index, 'time']
                results.append(result)
                pre_cut_index[device] = len(device_packets[device])
                break
    return results

def is_match(data_list,feature,pre_cut_index=0):

    data_table = pd.DataFrame(data_list).reset_index(drop=True)

    # 查询尾
    index = len(data_table) - 1
    # 最大查询长度
    max_window = max_length[data_table.loc[index,'device']]
    # 先匹配最后一位
    if data_table.loc[index,'datalength'] == feature['length'][len(feature['length'])-1]:

        index_packet_end = index
        index -=1
        feature_match_index = len(feature['length'])-2

        # 从后往前匹配
        while feature_match_index >= 0:

            if index <pre_cut_index:
                return False

            elif index_packet_end-index > max_window:
                return False

            elif data_table.loc[index,'datalength'] != feature['length'][feature_match_index]:
                index -= 1
            else:
                index -=1
                feature_match_index -= 1

        startTime= datetime.strptime(data_table.loc[index+1,'time'][:19],"%Y-%m-%d %H:%M:%S")
        endTime = datetime.strptime(data_table.loc[index_packet_end,'time'][:19],"%Y-%m-%d %H:%M:%S")
        if (endTime-startTime).seconds > 3:
            return False
        else:
            return True
    else:
        return False

if __name__ == "__main__":

    time_record = [] # record time

    dump_packets = AsyncSniffer(iface= netword_card,
                                filter=get_filter(device_mac_path))
    # dump_packets = AsyncSniffer(iface= netword_card)

    # 删除目录下的所有文件，以便本次抓取的存储
    delete_all_csv_file()
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

            # 检查是否之前是否有有效包
            is_exist, pre_csv = get_pre_csv()

            # 如果本次抓到有效包，
            if len(out_put) > 0:
                df = pd.DataFrame(out_put)

                # 存储下来
                file_index += 1
                save_packet(df,file_index)

                # 拼接之前的包
                csv_packets, recongize_index = combine_packets(is_exist,pre_csv,df)
                # 识别
                results = recognize(csv_packets, recongize_index)
                print(results)

                timeresults = pd.DataFrame(results)
                timeresults.to_csv(r'timeresults.csv', mode = 'a', index=0, encoding='utf_8_sig')

            # packets = recognizer.read_csv(csv_path)
            # # recognize
            # results = recognizer.recognize(packets, 0)
            # # take action
                for item in results:
                    recognizer.take_action(item)
        # except:
        #     print("stop sniff and save result")
            # if len(identify.final) > 0:
            #     identify.out_put_csv(file_out_path=result_path, file_name="result_real_time", time_tmp_record=True)
