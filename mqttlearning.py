import json
import time
import paho.mqtt.client as mqtt
from colorama import Fore

def subscribe_function(client: mqtt.Client):
     topic_lst = ['zigbee2mqtt/#']#,'zigbee2mqtt/philp_hue_light','zigbee2mqtt/philp_hue_light/availability']
     # - zigbee2mqtt/bridge/state
     # - zigbee2mqtt/0x001788010b57c9f2
     # - zigbee2mqtt/0x001788010b57c9f2/availability
     # - 
     for topic in topic_lst:
        client.subscribe(topic,0)
        print(Fore.RED+ "client subscibr topic : " + topic +" with qos: 0")
        
def unsubscribe_function(client: mqtt.Client):
     topic_lst = ['test/hello','test/asset','test']
     client.unsubscribe(topic_lst)
     print(Fore.GREEN+"client unsubscirbe topic: "+topic_lst)
     
def publish_function(client: mqtt.Client, deviceId: str=0x001788010b57c9f2):
    # zigbee2mqtt/bridge/request/permit_join zigbee2mqtt/bridge/response/touchlink/scan zigbee2mqtt/0x001788010b57c9f2 ON OFF
    topic = 'zigbee2mqtt/' + deviceId +'/set'
    dic_payload_on = {"state":"ON"}
    dic_payload_off = {"state":"OFF"}
    dic_payload_toggle = {"state":"TOGGLE"}
    
    payload_on = json.dumps(dic_payload_on)
    payload_off = json.dumps(dic_payload_off)
    payload_toggle = json.dumps(dic_payload_toggle)
    qos = 0
    retain = False
    client.publish(topic, payload_toggle, qos, retain)
    print(Fore.BLUE+"client publish topic: "+topic+" with payload: "+payload_toggle+" with qos: "+str(qos)+" with retain: "+str(retain))

def touchlinker_function(client: mqtt.Client):
    topic = 'zigbee2mqtt/bridge/request/permit_join'
    dic_payload = {"value":"true"}
    payload = json.dumps(dic_payload)
    qos = 0
    retain = False
    client.publish(topic, payload, qos, retain)
    print(Fore.BLUE+"client publish topic: "+topic+" with payload: "+payload+" with qos: "+str(qos)+" with retain: "+str(retain))

def allow_join(client: mqtt.Client):
    topic = 'zigbee2mqtt/bridge/request/permit_join'
    dic_payload = {"value":"true"}
    payload = json.dumps(dic_payload)
    qos = 0
    retain = False
    client.publish(topic, payload, qos, retain)
    print(Fore.BLUE+"client publish topic: "+topic+" with payload: "+payload+" with qos: "+str(qos)+" with retain: "+str(retain))
    
def disallow_join(client: mqtt.Client):
    topic = 'zigbee2mqtt/bridge/request/permit_join'
    dic_payload = {"value":"false"}
    payload = json.dumps(dic_payload)
    qos = 0
    retain = False
    client.publish(topic, payload, qos, retain)
    print(Fore.BLUE+"client publish topic: "+topic+" with payload: "+payload+" with qos: "+str(qos)+" with retain: "+str(retain))
    
def touchlink_scan(client: mqtt.Client):
    topic = 'zigbee2mqtt/bridge/request/touchlink/scan'
    qos = 0
    retain = False
    client.publish(topic, None, qos, retain)
    print(Fore.BLUE+"client publish topic: "+topic+" with payload: empty with qos: "+str(qos)+" with retain: "+str(retain))

def touchlink_factory_reset(client: mqtt.Client, device_id: str, channel: int):
    topic = 'zigbee2mqtt/bridge/request/touchlink/factory_reset'
    #{"ieee_address": "0x12345678", "channel": 12}
    dic_payload = {"ieee_address":device_id, "channel":channel}
    payload = json.dumps(dic_payload)
    qos = 0
    retain = False
    client.publish(topic, payload, qos, retain)
    print(Fore.BLUE+"client publish topic: "+topic+" with payload: "+payload+" with qos: "+str(qos)+" with retain: "+str(retain))

def remove_device(client: mqtt.Client, device_id: str):
    #zigbee2mqtt/bridge/request/device/remove
    topic = 'zigbee2mqtt/bridge/request/device/remove'
    dic_payload = {"id":device_id}
    payload = json.dumps(dic_payload)
    qos = 0
    retain = False
    client.publish(topic, payload, qos, retain)
    print(Fore.BLUE+"client publish topic: "+topic+" with payload: "+payload+" with qos: "+str(qos)+" with retain: "+str(retain))
    
def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))
    # client.subscribe("zigbee2mqtt/#")
    # client.subscribe("zigbee2mqtt/philp_hue_light

def on_message(client, userdata, msg):
    print(Fore.CYAN + msg.topic+" "+str(msg.payload))
    # print("message received ", str(msg.payload.decode("utf-8")))
    # print("message topic=", msg.topic)
    # print("message qos=", msg.qos)
    # print("message retain flag=", msg.retain)

def on_disconnect(client, userdata, rc):
    print("client disconnect")
    print("rc: " + str(rc))
    client.loop_stop()
     
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, transport='tcp')
# client.username_pw_set('flashmq')

# may need bind the client to 10.0.47.1 which is the veth5 ip
# test with local
# client.connect("0.0.0.0", 1883, 60)
# run with fuzzer

client.on_connect = on_connect
client.on_message = on_message
client.on_disconnect = on_disconnect
# client.on_disconnect = on_disconnect
client.connect("127.0.0.1", 1883, 60)
subscribe_function(client)
client.loop_start()

try:
    while 1:
        #publish_function(client)
        #touchlink_scan(client)
        touchlink_factory_reset(client, "0x001788010b57c9f2", 11)
        time.sleep(1)
except KeyboardInterrupt:
    client.disconnect()
    print("client disconnect")
    # client.loop_forever()
# subscribe_function(client)
'''
while 1:
     publish_function(client)
    #  on_message(client)
     time.sleep(1)

client.loop_forever()
'''
