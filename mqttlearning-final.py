import json
import time
import paho.mqtt.client as mqtt
from paho.mqtt.properties import Properties
from paho.mqtt.packettypes import PacketTypes
from colorama import Fore

from aalpy.learning_algs import run_Lstar
from aalpy.utils import visualize_automaton
from aalpy.base import SUL
from aalpy.oracles.StatePrefixEqOracle import StatePrefixEqOracle

DEVICE_ID = "0x001788010b57c9f2"

class ZigbeeMqttClient(SUL):
    def __init__(self, broker_address='localhost'):
        super().__init__()
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, transport='tcp', protocol=mqtt.MQTTv5)
        self.client.on_message = self.on_message
        self.client.connect(broker_address)
        self.response = None
        self.client.loop_start()

    def on_message(self, client, userdata, message):
        # Decode and capture the response payload
        payload = json.loads(message.payload.decode("utf-8"))
        self.response = payload
        print(f"{Fore.GREEN}<--- {message.topic}: {payload}")

    def publish_and_wait(self, request_topic, response_topic, payload, timeout=20):
        # Subscribe to the expected response topic
        self.client.subscribe(response_topic)
        
        # Publish the request message
        payload_str = json.dumps(payload)
        self.client.publish(request_topic, payload_str, qos=1)
        print(f"{Fore.CYAN}--> {request_topic} payload {payload_str}")

        # Wait for the response
        self.response = None  # Reset previous response
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.response is not None:
                response = self.response
                self.response = None  # Clear for future calls
                self.client.unsubscribe(response_topic)  # Unsubscribe after receiving response
                return response
            time.sleep(0.1)  # Avoid busy-waiting

        print(Fore.RED + "Timeout waiting for response")
        self.client.unsubscribe(response_topic)  # Unsubscribe if timeout occurs
        return None

    # Zigbee2MQTT-specific methods
    def default(self):
        return "invalid input provided"
    
    def restart(self):
        request_topic = 'zigbee2mqtt/bridge/request/restart'
        #response_topic = 'zigbee2mqtt/bridge/response/restart'
        response_topic = 'zigbee2mqtt/bridge/state'
        payload = {}
        response = self.publish_and_wait(request_topic, response_topic, payload)
        
        if response and response.get("state") == "online":
            print("Restart successful.")
        else:
            print("Restart failed or timed out.")
        return response
    
    def pre(self):
        pass
        #self.touchlink_scan()
        #self.touchlink_factory_reset()
        
    def post(self):
        pass
        #self.restart()
    
    def step(self, letter):
        requests = {
            "turn_on": {"method": self.turn_on, "args": [DEVICE_ID]},
            "turn_off": {"method": self.turn_off, "args": [DEVICE_ID]},
            "permit_join": {"method": self.permit_join, "args": []},
            "disallow_join": {"method": self.disallow_join, "args": []},
            "remove_device": {"method": self.remove_device, "args": [DEVICE_ID]}
        }
        
        request = requests.get(letter, {"method": self.default})
        output = request["method"](*request["args"])
        return output

    # Additional methods like touchlink_scan, permit_join, etc. would go here
    # "touchlink_scan": 'zigbee2mqtt/bridge/response/touchlink/scan',
    #     publish_message(client, 'zigbee2mqtt/bridge/request/touchlink/scan', None)
    # - zigbee2mqtt/bridge/state
    # - zigbee2mqtt/0x001788010b57c9f2
    # - zigbee2mqtt/0x001788010b57c9f2/availability
    # - 

    
    # Device Control Functions
    def device_state(self, device_id: str, state: str):
        request_topic = f'zigbee2mqtt/{device_id}/set'
        response_topic = f'zigbee2mqtt/{device_id}'
        payload = {"state": state}
        return self.publish_and_wait(request_topic, response_topic, payload)
    
    def turn_on(self, device_id: str):
        return self.device_state(device_id, "ON")
    
    def turn_off(self, device_id: str):
        return self.device_state(device_id, "OFF")
        

    def control_joining(self, allow: bool):
        request_topic = 'zigbee2mqtt/bridge/request/permit_join'
        response_topic = 'zigbee2mqtt/bridge/response/permit_join'
        payload = {"value": allow}
        return self.publish_and_wait(request_topic, response_topic, payload)
    
    def permit_join(self):
        return self.control_joining(True)
    
    def disallow_join(self):
        return self.control_joining(False)
    
    def touchlink_scan(self):
        request_topic = 'zigbee2mqtt/bridge/request/touchlink/scan'
        response_topic = 'zigbee2mqtt/bridge/response/touchlink/scan'
        #z2m:mqtt: MQTT publish: topic 'zigbee2mqtt/bridge/response/touchlink/scan', payload '{"data":{"found":[]},"status":"ok","transaction":"w8djq-14"}'
        result = self.publish_and_wait(request_topic, response_topic, "")
        if result and result.get("status") == "ok":
            print("Touchlink scan successful.")
            return result.get("data").get("found")
        else:
            print("Touchlink scan failed or timed out.")
        
    def touchlink_factory_reset(self, device_id: str=DEVICE_ID, channel: int=11):
        request_topic = 'zigbee2mqtt/bridge/request/touchlink/factory_reset'
        response_topic = 'zigbee2mqtt/bridge/response/touchlink/factory_reset'
        payload = {"ieee_address": device_id, "channel": channel}
        return self.publish_and_wait(request_topic, response_topic, payload)
        
    def remove_device(self, device_id: str=DEVICE_ID):
        request_topic = 'zigbee2mqtt/bridge/request/device/remove'
        response_topic = 'zigbee2mqtt/bridge/response/device/remove'
        payload = {"id": device_id}
        return self.publish_and_wait(request_topic, response_topic, payload)
    
    
alphabet = ["turn_on", "turn_off", "permit_join", "disallow_join", "remove_device"]
sul = ZigbeeMqttClient(broker_address="localhost")
    # Usage example for Zigbee2MQTT client

eq_oracle = StatePrefixEqOracle(alphabet, sul, walks_per_state=10, walk_len=10)

# run the learning algorithm
# internal caching is disabled, since we require an error handling for possible non-deterministic behavior
learned_model = run_Lstar(alphabet, sul, eq_oracle, automaton_type='mealy',cache_and_non_det_check=False, print_level=0)

# visualize the automaton
visualize_automaton(learned_model, path="learnedModel.pdf", file_type='pdf')
'''
try:
    # Restart the Zigbee bridge and wait for confirmation
    #result = zigbee_client.restart()
    #result = zigbee_client.touchlink_scan()
    #result = zigbee_client.device_state("0x001788010b57c9f2", "TOGGLE")
    #result = zigbee_client.control_joining(True)
    #result = zigbee_client.touchlink_factory_reset("0x001788010b57c9f2", 11)
    result = zigbee_client.remove_device("0x001788010b57c9f2")
    if result:
        print(f"response: {result}")

except KeyboardInterrupt:
    zigbee_client.client.disconnect()
    zigbee_client.client.loop_stop()
    print("Client disconnected")
'''