import json
import time
import paho.mqtt.client as mqtt
from paho.mqtt.properties import Properties
from paho.mqtt.packettypes import PacketTypes
from colorama import Fore
#logger
import logging

from aalpy.learning_algs import run_Lstar
from aalpy.learning_algs import run_KV
from aalpy.utils import visualize_automaton
from aalpy.base import SUL
from aalpy.oracles.StatePrefixEqOracle import StatePrefixEqOracle
from aalpy.oracles.RandomWalkEqOracle import RandomWalkEqOracle

DEVICE_ID = "0x001788010b57c9f2"
ERROR = "error"
WAIT_TIME = 1

# Set up console and file logger
logging.basicConfig(level=logging.INFO, format=Fore.RESET+'%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

class ZigbeeMqttClient(SUL):
    def __init__(self, broker_address='localhost'):
        super().__init__()
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, transport='tcp', protocol=mqtt.MQTTv5)
        self.client.on_message = self.on_message
        self.client.connect(broker_address)
        self.response = None
        self.client.loop_start()
        self.connection_error_counter = 0

    def on_message(self, client, userdata, message):
        # Decode and capture the response payload
        payload = json.loads(message.payload.decode("utf-8"))
        self.response = payload
        logging.debug(f"{Fore.GREEN}<--- {message.topic}: {payload}")
        

    def publish_and_wait(self, request_topic, response_topic, payload, timeout=20):
        # Subscribe to the expected response topic
        self.client.subscribe(response_topic)
        
        # Publish the request message
        payload_str = json.dumps(payload)
        self.client.publish(request_topic, payload_str, qos=1)
        logging.debug(f"{Fore.CYAN}--> {request_topic} payload {payload_str}")

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

        logging.debug(Fore.RED + "Timeout waiting for response")
        self.client.unsubscribe(response_topic)  # Unsubscribe if timeout occurs
        return None

    # Zigbee2MQTT-specific methods
    def default(self):
        return "invalid input provided"
        
    def pre(self):
        logging.info("====  Preparation   ====")
        self.in_pre = True
        self.control_joining(True)
        while True:
            response = self.get_device_state(DEVICE_ID)
            if response == "OFF":
                self.device_state(DEVICE_ID, "ON")
                break
            elif response == ERROR:
                time.sleep(8)
            else:
                break
        self.in_pre = False
        logging.info("====      Done      ====")
        pass
        #self.touchlink_scan()
        #self.touchlink_factory_reset()
        
    def post(self):
        logging.info("____Round Done______")
        #self.restart()
        pass
    
    def step(self, letter):
        requests = {
            "turn_on": {"method": self.device_state, "args": [DEVICE_ID, "ON"]},
            "turn_off": {"method": self.device_state, "args": [DEVICE_ID, "OFF"]},
            "toggle": {"method": self.device_state, "args": [DEVICE_ID, "TOGGLE"]},
            "get_state": {"method": self.get_device_state, "args": [DEVICE_ID]},
            "permit_join": {"method": self.control_joining, "args": [True]},
            "forbid_join": {"method": self.control_joining, "args": [False]},
            "remove_device": {"method": self.remove_device, "args": [DEVICE_ID]},
        }
        
        request = requests.get(letter, {"method": self.default})
        output = request["method"](*request["args"])
        return output
    
    # Device Control Functions
    
    def restart(self):
        request_topic = 'zigbee2mqtt/bridge/request/restart'
        #response_topic = 'zigbee2mqtt/bridge/response/restart'
        response_topic = 'zigbee2mqtt/bridge/state'
        payload = {}
        response = self.publish_and_wait(request_topic, response_topic, payload)
        
        if response and response.get("state") == "online":
            logging.info(f"{Fore.MAGENTA}Restart successful.")
        else:
            logging.info(f"{Fore.MAGENTA}Restart failed or timed out.")
        return response
    
    def device_state(self, device_id: str, state: str):
        request_topic = f'zigbee2mqtt/{device_id}/set'
        response_topic = f'zigbee2mqtt/{device_id}'
        payload = {"state": state}
        response = self.publish_and_wait(request_topic, response_topic, payload, timeout=3)
        
        if response and response.get("state") is not None:
            logging.info(f"{Fore.MAGENTA}Device {device_id} turned {state}.")
            time.sleep(WAIT_TIME)
            return f"{response.get('state')}"
        else:
            logging.info(f"{Fore.MAGENTA}Failed to turn device {device_id} {state}.")
            return ERROR
        
    def get_device_state(self, device_id: str):
        request_topic = f'zigbee2mqtt/{device_id}/get'
        response_topic = f'zigbee2mqtt/{device_id}'
        payload = {"state": ""}
        response = self.publish_and_wait(request_topic, response_topic, payload, timeout=3)
        
        if response:
            logging.info(f"{Fore.MAGENTA}Device {device_id} state: {response.get('state')}.")
            time.sleep(WAIT_TIME)
            return f"{response.get('state')}"
        else:
            logging.info(f"{Fore.MAGENTA}Failed to get device {device_id} state.")
            return ERROR
    
    def control_joining(self, allow: bool):
        request_topic = 'zigbee2mqtt/bridge/request/permit_join'
        response_topic = 'zigbee2mqtt/bridge/response/permit_join'
        payload = {"value": allow}
        response = self.publish_and_wait(request_topic, response_topic, payload)
        if response and response.get("status") == "ok":
            logging.info(f"{Fore.MAGENTA}Joining {'allowed' if allow else 'disallowed'}.")
            time.sleep(WAIT_TIME)
            if not self.in_pre and allow:
                while self.get_device_state(DEVICE_ID) == ERROR:
                    time.sleep(8)
                return f"{response.get('data').get('value')}"
            else:
                return f"{response.get('data').get('value')}"
        return ERROR
        
    def touchlink_scan(self):
        request_topic = 'zigbee2mqtt/bridge/request/touchlink/scan'
        response_topic = 'zigbee2mqtt/bridge/response/touchlink/scan'
        #z2m:mqtt: MQTT publish: topic 'zigbee2mqtt/bridge/response/touchlink/scan', payload '{"data":{"found":[]},"status":"ok","transaction":"w8djq-14"}'
        result = self.publish_and_wait(request_topic, response_topic, "")
        if result and result.get("status") == "ok":
            logging.info(f"{Fore.MAGENTA}Touchlink scan successful.")
            return result.get("data").get("found")
        else:
            logging.info(f"{Fore.MAGENTA}Touchlink scan failed or timed out.")
        
    def touchlink_factory_reset(self, device_id: str=DEVICE_ID, channel: int=11):
        request_topic = 'zigbee2mqtt/bridge/request/touchlink/factory_reset'
        response_topic = 'zigbee2mqtt/bridge/response/touchlink/factory_reset'
        payload = {"ieee_address": device_id, "channel": channel}
        return self.publish_and_wait(request_topic, response_topic, payload)
        
    def remove_device(self, device_id: str=DEVICE_ID):
        request_topic = 'zigbee2mqtt/bridge/request/device/remove'
        response_topic = 'zigbee2mqtt/bridge/response/device/remove'
        #response_topic = 'zigbee2mqtt/bridge/event'
        payload = {"id": device_id}
        response = self.publish_and_wait(request_topic, response_topic, payload, timeout=3)
        if response and response.get("status") == "ok": #response.get("type") == "device_leave"
            logging.info(f"{Fore.MAGENTA}Device {device_id} removed.")
            return response.get("status")
        logging.info(f"{Fore.MAGENTA}Failed to remove device {device_id}.")
        return ERROR
    
    
alphabet = ["turn_on", "turn_off", "get_state"]#, "permit_join", "forbid_join", "remove_device"]#"toggle", ]
sul = ZigbeeMqttClient(broker_address="localhost")
    # Usage example for Zigbee2MQTT client

eq_oracle = StatePrefixEqOracle(alphabet, sul, walks_per_state=2, walk_len=2)
#eq_oracle = RandomWalkEqOracle(alphabet, sul, num_steps=5)

# run the learning algorithm
# internal caching is disabled, since we require an error handling for possible non-deterministic behavior
learned_model = run_Lstar(alphabet, sul, eq_oracle, automaton_type='mealy',cache_and_non_det_check=True, print_level=3)
#learned_model = run_KV(alphabet, sul, eq_oracle, automaton_type='mealy', cache_and_non_det_check=True, print_level=3)

# visualize the automaton
visualize_automaton(learned_model, path="learnedModel.pdf", file_type='pdf')

try:
    # Restart the Zigbee bridge and wait for confirmation
    #result = zigbee_client.restart()
    #result = zigbee_client.touchlink_scan()
    result = sul.device_state("0x001788010b57c9f2", "TOGGLE")
    #result = zigbee_client.control_joining(True)
    #result = zigbee_client.touchlink_factory_reset("0x001788010b57c9f2", 11)
    #result = zigbee_client.remove_device("0x001788010b57c9f2")
    if result:
        logging.info(f"response: {result}")

except KeyboardInterrupt:
    sul.client.disconnect()
    sul.client.loop_stop()
    logging.info("Client disconnected")