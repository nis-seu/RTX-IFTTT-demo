# -!- coding: utf-8 -!-
from datetime import datetime
import demo.util.deal_csv as dl
import requests

# window
max_length = {
    'Yeelight_LED_Bulb_1': 4,
    'wemo_switch': 5,
}
device_mac_path = r"../file/feature/Device_MAC.csv"
# device_mac_path = "/root/upload/demo/file/feature/Device_MAC.csv"
# webhook
user_key = "xxx---xxx"
operation_event_name = {"wemo_switch manual/timer on/off": 'test_wemo'
                        # webhook-action URL
                        }# key=device operation


def get_device_list():
    mac_df = dl.read_csv(device_mac_path)

    de = []
    for item in mac_df:
        if item[1] != 'Device':
            de.append(item[1])

    device_packets = {}
    for item in de:
        device_packets[item] = []
    return device_packets

def set_Pre_Cut_Index():
    pre_cut_index = {}
    for key in max_length:
        pre_cut_index[key] =0
    return pre_cut_index

def recognize(csv_packets):

    device_packets = get_device_list()

    results = []

    # 设置匹配的终点
    pre_cut_index = set_Pre_Cut_Index()
    # 循环识别流量
    for index in range(0,len(csv_packets)):
        # 获取设备名
        device = csv_packets[index]['device']
        # 把流量加入设备对应的packets
        device_packets[device].append(csv_packets[index])
        # 获取设备对应的features
        features = get_features(str(device).lower())
        # 检查当前是否有特征匹配
        for index_features in range(len(features)):
            if is_match(device_packets[device], features[index_features],pre_cut_index[device]):
                result = {}
                result['device'] = device
                result['operation'] = features[index_features]['Operation']
                result['time'] = csv_packets[index]['time']
                results.append(result)
                pre_cut_index[device] = len(device_packets[device])
                break
    return results

def is_match(data_list,feature,pre_cut_index=0):

    data_table = data_list

    # 查询尾
    index = len(data_table) - 1
    # 最大查询长度
    max_window = max_length[data_table[index]['device']]
    # 先匹配最后一位
    if data_table[index]['datalength'] == feature['length'][len(feature['length'])-1]:

        index_packet_end = index
        index -=1
        feature_match_index = len(feature['length'])-2

        # 从后往前匹配
        while feature_match_index >= 0:

            if index <pre_cut_index:
                return False

            elif index_packet_end-index > max_window:
                return False

            elif data_table[index]['datalength'] != feature['length'][feature_match_index]:
                index -= 1
            else:
                index -=1
                feature_match_index -= 1

        startTime= datetime.strptime(data_table[index+1]['time'][:19],"%Y-%m-%d %H:%M:%S")
        endTime = datetime.strptime(data_table[index_packet_end]['time'][:19],"%Y-%m-%d %H:%M:%S")
        if (endTime-startTime).seconds > 3:
            return False
        else:
            return True
    else:
        return False


def get_features(device):
    feature_file = dl.read_csv("../file/feature/feature_"+device+".csv")
    # feature_file = dl.read_csv("/root/upload/demo/file/feature/feature_"+device+".csv")
    features = []
    feature_num = len(feature_file[0])
    for index in range(1, len(feature_file)):
        line = feature_file[index]
        feature = {}
        feature['Operation'] = line[2]
        feature['length'] = []
        for i in range(4,feature_num):
            if line[i] != '0':
                feature['length'].append(int(line[i]))
        features.append(feature)
    return features


def take_action(info):
    key = info['device']+" "+info['operation']
    print(key)
    if key in operation_event_name.keys():
        trigger_webhook(key)


def trigger_webhook(key):
    """
    """
    url = "https://maker.ifttt.com/trigger/"+operation_event_name[key]+"/with/key/" + user_key
    post_time = datetime.now()
    print("post-time"+(post_time.strftime("%Y-%m-%d %H:%M:%S.%f")))
    state = requests.post(url)  # t2
    response_time = post_time + state.elapsed
    print("response_time"+response_time.strftime("%Y-%m-%d %H:%M:%S.%f") )
    print(state.text)  # "Congratulations! You've fired the tuya_motion_active event"
    print("the consuming time of executing webhook applet:", state.elapsed.total_seconds(), "s")

# if __name__ == "__main__":
    # pre = [{'time': '2021-12-24 17:24:38.066775', 'proto': 'TCP', 'src_mac': '14:91:82:ca:1d:a1', 'dst_mac': '86:5c:f3:86:87:d3', 'src_ip': '192.168.137.209', 'sport': 3565, 'dst_ip': '3.215.61.189', 'dport': 8883, 'seq': 3444953964, 'ack': 792342014, 'device': 'wemo_switch', 'datalength': 3220}, {'time': '2021-12-24 17:24:38.305149', 'proto': 'TCP', 'src_mac': '86:5c:f3:86:87:d3', 'dst_mac': '14:91:82:ca:1d:a1', 'src_ip': '3.215.61.189', 'sport': 8883, 'dst_ip': '192.168.137.209', 'dport': 3565, 'seq': 792342014, 'ack': 3444954286, 'device': 'wemo_switch', 'datalength': 331}]
    #
    # results = recognize(pre)
    #
    # print(results)
