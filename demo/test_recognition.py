# -!- coding: utf-8 -!-
from datetime import datetime
import demo.deal_csv as dl
import requests

max_length = {
    'Yeelight_LED_Bulb_1': 4,
    'wemo_switch': 4,
}
device_mac_path = r"file/feature/Device_MAC.csv"
# device_mac_path = "/root/upload/demo/file/feature/Device_MAC.csv"
user_key = "xxx---xxx"
operation_event_name = {"wemo_switch manual/timer on/off": 'test_wemo'
                        }# key=device operation


# get the devices from Device_MAC.csv
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

# the start index of traffic
def set_Pre_Cut_Index():
    pre_cut_index = {}
    for key in max_length:
        pre_cut_index[key] =0
    return pre_cut_index

#  recognize the state change of devices
def recognize(csv_packets):
    device_packets = get_device_list()
    results = []
    pre_cut_index = set_Pre_Cut_Index()
    for index in range(0,len(csv_packets)):
        device = csv_packets[index]['device']
        device_packets[device].append(csv_packets[index])
        features = get_features(str(device).lower())
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

# match traffic with the feature file
def is_match(data_list,feature,pre_cut_index=0):
    data_table = data_list
    index = len(data_table) - 1
    max_window = max_length[data_table[index]['device']]
    if data_table[index]['datalength'] == feature['length'][len(feature['length'])-1]:
        index_packet_end = index
        index -=1
        feature_match_index = len(feature['length'])-2
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

# read the feature file
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


# take action according to the state change of devices
def take_action(info):
    key = info['device']+" "+info['operation']
    print(key)
    if key in operation_event_name.keys():
        trigger_webhook(key)

# send an notification to the IFTTT
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

