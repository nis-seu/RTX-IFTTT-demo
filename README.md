# Code for Real-Time Execution of Trigger-Action Connection for Home Internet-of-Things
##  Devices
### Belkin Wemo Smart Plug
### Yeelight LED Bulb 1
## Usage of IFTTT
### 1. Create an Applet
### 2. Add a Trigger, choose "WeMo Smart Plug" service, choose "Switched on" trigger and then choose your Wemo Smart Plug.
### 3. Add a Action, choose "Yeelight" service, choose "Toggle lights on/off" trigger and then choose your Yeelight LED Bulb 1.
### 4. In Wemo App, you can switch on your Wemo  Smart Plug's Button. After about 60 seconds, the Yeelight LED Bulb 1 will be turned on.
## Usage of Code
### 1.Create an Applet, and then choose webhooks as trigger service  and choose Yeelight as Action service.
### 2.Modify the Code
#### 2.1 insert your devices's MAC address in the Device_MAC.csv
#### 2.2 insert your devices's traffic feature in the feature_{device}.csv.
#### 2.3 set your netword card in real_time.py
#### 2.4 set your webhook user_key
#### 2.5 set your operation_event_name in which key is made up of wemo device and operation , value is the eventName. 
### 3.run the real_time.py, and then turn on the Wemo Smart Plug. After about 6 seconds, the Yeelight LED Bulb 1 will be turned on.
## Auther
### 1. kai dong. E-mail: dk@seu.edu.cn
### 2. Yakun Zhang. E-mail: zyk@seu.edu.cn
### 3. Yuchen Zhao. E-mail: zyc@seu.edu.cn
### 4. Daoming Li. E-mail: lidaoming0219@seu.edu.cn
