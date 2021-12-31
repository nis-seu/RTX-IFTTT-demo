# A  guide to run the demo
This article aims to help readers implement the Webhook mechanism of RTX-IFTTT with the code we provide. The essence of this demo is to identify the behavior of devices by capturing the traffic characteristics of IoT devices, and then send a notification for IFTTT in real-time. In IFTTT, the timely response of Webhook is used to shorten the delay.
##  Devices 
Belkin Wemo Smart Plug Model:F7C027.  
Yeelight Smart LED Bulb (Color) YLDP06YL LED E27.  
(Optional) Brume(GL-MV1000)/Notebook.  
## Development Environment
+ Python 3.7
    - scapy  
    - datetime  
    - requests  

## File Structure
```
.  
|--file--|--feature--|--Device_MAC.csv                   # store device and MAC
|--file--|--feature--|--feature_wemo_switch.csv          # store the fingerprint of Wemo Smart Plug
|--file--|--feature--|--feature_yeelight_led_bulb_1.csv  # store the fingerprint of Yeelight LED Bulb
|--deal_csv.py                                           # the helper for other python file
|--final_parse_packet.py                                 # the code of parsing the route traffic
|--real_time.py                                          # the main function to run 
|--test_recognition.py                                   # the code of recognize the state changes of devices
```


## Create an Applet in IFTTT
1. Go to the IFTTT website and then click the "Create" button.
2. Click the "Add" button to add a Trigger. After that, choose the "WeMo Smart Plug" service and then choose "Switched on" trigger.  After binding your Wemo Account with IFTTT, choose your Wemo Device.
3. Click the "Add" button to add an Action. After that, choose "Yeelight" service and then choose "Toggle lights on/off" trigger. After binding your Yeelight Account with IFTTT, choose your Yeelight LED Bulb .
## Test the Applet
4. In Wemo App, switch on your Wemo  Smart Plug. After about 60 seconds, the Yeelight LED Bulb will be turned on.

## Create a new Webhook
 Create an  Applet like "Create an Applet in IFTTT", and then choose Webhooks as trigger service and choose Yeelight as Action service. The "event_name" is what you set in the Webhooks service.
## Create a new "Trigger-Webhook" Applet
 Modify the Code:
  1. Insert your devices's MAC address in the Device_MAC.csv. You can find the mac of device on the label of device.
  2. Insert your devices' traffic feature in the feature_{device}.csv. Compared with PingPong, the same type of device may have different characteristics. A sample way to achieve the traffic feature is analyzing the packets using Wireshark, and then manually writing to feature_{device}.csv
  3. Set your netword card in real_time.py. You can use "show_interfaces()" function of "scapy.all" to find the netword card of your Route/PC. Determine which network adapter sends and receives device traffic by listening on the traffic of a fixed MAC address. In Brume(GL-MV1000), the netword card is "br-lan".
  4. Set your webhook "user_key". Visit the website "https://ifttt.com/maker_webhooks" and Click the "Documentation" Button. Your key is in the first line.
  5. Set your operation_event_name in which key is made up of wemo device and operation, value is the "event_name".
  6. If you use route(like, Brume(GL-MV1000)) to run the code, the file path of this project should be set to the Absolute Path (AP).
## Run the new Applet in real time
 Run the real_time.py, and then turn on the Wemo Smart Plug. After about 6 seconds, the Yeelight LED Bulb will be turned on.
## Contacts 
 1. Daoming Li. E-mail: lidaoming0219@seu.edu.cn
 2. Yuchen Zhao. E-mail: zyc@seu.edu.cn  
 3. Kai Dong. E-mail: dk@seu.edu.cn


