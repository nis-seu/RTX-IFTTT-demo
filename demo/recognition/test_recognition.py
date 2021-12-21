# -!- coding: utf-8 -!-
import datetime
import os
import re
import time
import pandas as pd
import requests

# file_path
file_path = r"../file/packets/mijia_switch/test_dataset/APP_switch/"
file_name = "100"

# window
max_length = {
    'Yeelight_LED_Bulb_1': 4,
    'wemo_switch': 5,
}

# webhook
webhook_url_module = "https://maker.ifttt.com/trigger/{event_name}/with/key/{user_key}"
user_key = "xxx-xxx"
url_key = re.sub("{user_key}", user_key, webhook_url_module)
operation_event_name = {"device operation": 'eventName'
                        # webhook-action URL
                        }# key=device operation


def read_csv(csv_file):
    packets = {
        'Yeelight_LED_Bulb_1': [],
        'wemo_switch': []
            }
    csv_table = pd.read_csv(csv_file, date_parser='time', encoding='utf-8')
    for each in range(len(csv_table)):
        packets[csv_table.loc[each, 'device']].append(csv_table.loc[each])
    return packets

def recognize(packets,start,write_path):
    results = []
    for device in packets:
        if len(packets[device])==0:
            continue
        data_table = pd.DataFrame(packets[device]).reset_index(drop=True)
        # get features
        features = get_features(str(device).lower())

        # 打开要写入的文件
        file = open(write_path, "a", encoding='utf-8')
        # for item in results:
        #     file.write(str(item) + '\n')

        pre_cut_index = 0
        for index_packet in range(len(data_table)):
            result = {}
            for index_features in range(len(features)):
                if is_match(data_table,features[index_features],index_packet,pre_cut_index):
                    # 得到结果

                    result['time'] = data_table.loc[index_packet,'time']
                    result['device'] = device
                    result['operation'] = features[index_features]['Operation']
                    results.append(result)
                    # 设置下一个匹配的最左端
                    pre_cut_index = index_packet+1
                    # 跳出当前循环，匹配下一个包
                    break
            # 写入文件
            file.write(str(data_table.loc[index_packet].to_list())+'\n')
            if len(result) != 0:
                file.write(str(result)+'\n')
    return results

def is_match(data_table,feature,index,pre_cut_index=0):
    max_window = max_length[data_table.loc[index,'device']]
    if data_table.loc[index,'datalength'] == feature['length'][len(feature['length'])-1]:
        index_packet_end = index
        index -=1
        feature_match_index = len(feature['length'])-2
        while feature_match_index >= 0:
            if index < pre_cut_index:
                return False
            elif index_packet_end-index > max_window:
                return False
            elif data_table.loc[index,'datalength'] != feature['length'][feature_match_index]:
                index -= 1
            else:
                index -=1
                feature_match_index -= 1
        startTime= datetime.datetime.strptime(data_table.loc[index+1,'time'][:19],"%Y-%m-%d %H:%M:%S")
        endTime = datetime.datetime.strptime(data_table.loc[index_packet_end,'time'][:19],"%Y-%m-%d %H:%M:%S")
        if (endTime-startTime).seconds > 2:
            return False
        else:
            return True
    else:
        return False





def get_features(device):
    feature_file = pd.read_csv("../file/feature/feature_"+device+".csv",encoding='gbk')
    features = []
    for index in range(len(feature_file)):
        line = feature_file.loc[index].to_list()
        feature = {}
        feature['Operation'] = line[2]
        feature['length'] = []
        for i in range(4,len(line)):
            if line[i]!=0:
                feature['length'].append(line[i])
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
    url = re.sub("{event_name}", operation_event_name[key], url_key)
    post_time = datetime.datetime.now()
    print("post-time"+(post_time.strftime("%Y-%m-%d %H:%M:%S.%f")))
    state = requests.post(url)  # t2
    response_time = post_time + state.elapsed
    print("response_time"+response_time.strftime("%Y-%m-%d %H:%M:%S.%f") )
    print(state.text)  # "Congratulations! You've fired the tuya_motion_active event"
    print("the consuming time of executing webhook applet:", state.elapsed.total_seconds(), "s")

if __name__ == "__main__":

    csv_path = file_path + file_name + ".csv"
    write_path = file_path+"recognize_"+file_name+".txt"

    packets = read_csv(csv_path)
    # recognize
    results = recognize(packets,0,write_path)
    num = {}
    for item in results:
        key = str(item['device'])+" "+str(item['operation'])
        if num.__contains__(key):
            num[key] +=1;
        else:
            num[key] =1;

    file = open(write_path,"a",encoding='utf-8')
    # for item in results:
    #     file.write(str(item)+'\n')
    for item in num:
        print(item)
        print(num[item])
    # take action
    # for item in results:
    #     take_action(item)