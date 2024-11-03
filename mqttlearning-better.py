import json
import threading
import time
import paho.mqtt.client as mqtt
from colorama import Fore

# Constants for Topics
SUBSCRIBE_TOPICS = ['zigbee2mqtt/#']
UNSUBSCRIBE_TOPICS = ['test/hello', 'test/asset', 'test']

# Helper function to handle publishing
def publish_message(client: mqtt.Client, topic: str, payload: dict = None, qos: int = 0, retain: bool = False):
    payload_str = json.dumps(payload) if payload else ""
    client.publish(topic, payload_str, qos, retain)
    print(Fore.BLUE + f"Published to topic: {topic}, payload: {payload_str}, QoS: {qos}, retain: {retain}")

# Subscription and Unsubscription Functions
def subscribe_to_topics(client: mqtt.Client, topics=SUBSCRIBE_TOPICS):
    for topic in topics:
        client.subscribe(topic, qos=0)
        print(Fore.RED + f"Subscribed to topic: {topic} with QoS: 0")

def unsubscribe_from_topics(client: mqtt.Client, topics=UNSUBSCRIBE_TOPICS):
    client.unsubscribe(topics)
    print(Fore.GREEN + f"Unsubscribed from topics: {topics}")

# Device Control Functions
def publish_device_state(client: mqtt.Client, device_id: str, state: str):
    topic = f'zigbee2mqtt/{device_id}/set'
    payload = {"state": state}
    publish_message(client, topic, payload)

def control_joining(client: mqtt.Client, allow: bool):
    topic = 'zigbee2mqtt/bridge/request/permit_join'
    payload = {"value": str(allow).lower()}
    publish_message(client, topic, payload)

RESPONSE_TOPICS = {
    "touchlink_scan": 'zigbee2mqtt/bridge/response/touchlink/scan',
    # Add other topics if needed
}
    
def restart_zigbee2mqtt(client: mqtt.Client):
    topic = 'zigbee2mqtt/bridge/request/restart'
    publish_message(client, topic)

# Blocking function for touchlink_scan
def touchlink_scan(client: mqtt.Client):
    # Event to wait for the specific message
    response_event = threading.Event()
    response_payload = {}

    def on_response(client, userdata, msg):
        # Check if the topic and payload match what we're waiting for
        if msg.topic == RESPONSE_TOPICS["touchlink_scan"]:
            payload = json.loads(msg.payload.decode("utf-8"))
            # Check if payload matches expected format or is empty
            if payload == {"data": {"found": [{"channel": 11, "ieee_address": "0x001788010b57c9f2"}]}, "status": "ok"} or not payload:
                response_payload["result"] = payload
                response_event.set()  # Signal that we received the expected message

    # Temporarily override the on_message to handle only specific responses
    client.message_callback_add(RESPONSE_TOPICS["touchlink_scan"], on_response)
    # Subscribe only to the response topic
    client.subscribe(RESPONSE_TOPICS["touchlink_scan"])

    # Publish the scan request
    publish_message(client, 'zigbee2mqtt/bridge/request/touchlink/scan', None)

    # Wait until the expected message is received or timeout
    if response_event.wait(timeout=15):  # Wait up to 10 seconds
        print(Fore.GREEN + "Received expected response for touchlink_scan")
        result = response_payload["result"]
    else:
        print(Fore.RED + "Timeout waiting for response to touchlink_scan")
        result = None  # Or handle timeout as needed

    # Clean up: Unsubscribe and remove the custom callback
    client.unsubscribe(RESPONSE_TOPICS["touchlink_scan"])
    client.message_callback_remove(RESPONSE_TOPICS["touchlink_scan"])

    return result


def touchlink_factory_reset(client: mqtt.Client, device_id: str, channel: int):
    topic = 'zigbee2mqtt/bridge/request/touchlink/factory_reset'
    payload = {"ieee_address": device_id, "channel": channel}
    publish_message(client, topic, payload)

def remove_device(client: mqtt.Client, device_id: str):
    topic = 'zigbee2mqtt/bridge/request/device/remove'
    payload = {"id": device_id}
    publish_message(client, topic, payload)

# MQTT Callbacks
def on_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc))

def on_message(client, userdata, msg):
    print(Fore.CYAN + f"{msg.topic} {str(msg.payload)}")

def on_disconnect(client, userdata, rc):
    print("Disconnected with result code " + str(rc))
    client.loop_stop()

# Client Setup
client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message
client.on_disconnect = on_disconnect
client.connect("127.0.0.1", 1883, 60)

# Start Client Loop
client.loop_start()
subscribe_to_topics(client)

try:
    restart_zigbee2mqtt(client)
    time.sleep(5)
    result = touchlink_scan(client)
    if result:
        print(Fore.YELLOW + f"Touchlink scan result: {result}")
    else:
        print(Fore.YELLOW + "No devices found during touchlink scan.")
except KeyboardInterrupt:
    client.disconnect()
    print("Client disconnected")
