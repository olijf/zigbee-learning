from random import randint
from zigbee_frames.transceive import Transceiver
from util.wpan_interface import Phy
from scapy.all import Packet, sendp, AsyncSniffer
from scapy.layers.zigbee import ZigbeeNWK, ZigbeeClusterLibrary, ZCLGeneralReadAttributesResponse, ZCLReadAttributeStatusRecord, ZCLGeneralDefaultResponse, ZDPDeviceAnnce
from scapy.layers.dot15d4 import Dot15d4Beacon, Dot15d4Cmd, Dot15d4
from util.crypto import CryptoUtils
from zigbee_frames.frameprovider import FrameProvider
from threading import Thread
import logging
from colorama import Fore
import time
from typing import Tuple

from aalpy.learning_algs import run_Lstar
from aalpy.learning_algs import run_KV
from aalpy.utils import visualize_automaton
from aalpy.base import SUL
from aalpy.oracles.StatePrefixEqOracle import StatePrefixEqOracle
from aalpy.oracles.RandomWalkEqOracle import RandomWalkEqOracle


# Set up console logger
logging.basicConfig(level=logging.INFO, format=Fore.RESET+'%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

ERROR = "error"
# set up the database
database = {
    "network_key" : bytes.fromhex("31701f12dd93150ec4efce97e381ef06"),
    "extended_source_addr" : bytes.fromhex("00:12:4b:00:1c:dd:27:3d".replace(":", "")),
    "pan_id" : 0x1a62,
    "target_node" : 0x26cd,
    "nodes" : {},
    "wait_time_for_packet_response" : 3,
    "wait_time_in_between_steps" : 1.5,
    "interface" : "wpan0",
    "frame_counter" : randint(0, 255)
    }
class ZigbeeSpoofer:
    def __init__(self, frame_provider: FrameProvider):
        self.frame_provider = frame_provider
        self.done = False
        self.thread = Thread(target=self.spoofing_loop).start()
        
    def spoofing_loop(self):
        while not self.done:
            logging.debug("Sending link status and route request")
            link_status_frame = self.frame_provider.link_status(database["pan_id"])
            logging.debug(f"{Fore.BLUE}---> Packet: {link_status_frame.summary()}")
            #sendp(link_status_frame, iface="wpan0", verbose=0)
            route_request_frame = self.frame_provider.many_to_one_route_request(0xfffd, database["pan_id"])
            logging.debug(f"{Fore.BLUE}---> Packet: {route_request_frame.summary()}")
            sendp(route_request_frame, iface="wpan0", verbose=0)
            time.sleep(5)
            
class ZigBeacon:
    def __init__(self, frame_provider: FrameProvider):
        self.frame_provider = frame_provider
        self.done = False
        #self.thread = Thread(target=self.beacon_loop).start()
        AsyncSniffer(iface=database['interface'], prn=self.process_sniffer_frames, store=False, stop_filter=lambda _: self.done).start()
    
    def process_sniffer_frames(self, packet):
        packet = Dot15d4(packet.do_build())
        logging.debug(f"{Fore.GREEN}<--- Packet: {packet.summary()}")        
        if packet.haslayer(Dot15d4Cmd) and packet.cmd_id == 7:
            logging.info(f"{Fore.MAGENTA}got a beacon request {packet.summary()}")
            reply = self.frame_provider.beacon(database["pan_id"], 0x0, database["extended_source_addr"])
            logging.debug(f"{Fore.BLUE}---> Packet: {reply.summary()}")
            sendp(reply, iface="wpan0", verbose=0)
        elif packet.haslayer(ZigbeeNWK) and packet.flags & 16:   
            logging.debug(f"{Fore.YELLOW}extended source found: {packet.ext_src:016x}")
            if packet.src_addr not in database["nodes"]:
                logging.debug(f"{Fore.YELLOW}adding node to database")
                database["nodes"][packet.src_addr] = packet.ext_src.to_bytes(8, 'big')
        elif packet.haslayer(ZigbeeNWK) and packet.flags & 2 and packet.src_addr in database["nodes"]:
                logging.debug(f"network key: {database['network_key'].hex()}")
                decrypted_payload, success = CryptoUtils.zigbee_packet_decrypt(database['network_key'], packet, database["nodes"][packet.src_addr])
                if success:
                    logging.info(f"{Fore.YELLOW}decoded frame {decrypted_payload.summary()}")
                    if decrypted_payload.haslayer(ZDPDeviceAnnce):
                        logging.info(f"{Fore.CYAN}got a device announcement {decrypted_payload.show()}")
                        #-->> send this out using the proper FrameProvider 
                        reply = self.frame_provider.copy_device_annouce(decrypted_payload, database["pan_id"], 0xffff)
                        decrypt, _ = CryptoUtils.zigbee_packet_decrypt(database['network_key'], reply, database["nodes"][0x0000])
                        logging.info(f"{Fore.BLUE}---> Packet: {decrypt.summary()}")
                        logging.debug(f"{Fore.BLUE}---> Packet: {reply.summary()}")
                        sendp(reply, iface="wpan0", verbose=0)

class ZigbeeInjectionClient(SUL):
    def __init__(self):
        super().__init__()        
        self.phy = Phy(int.from_bytes(database["extended_source_addr"]), initial_channel=11, pan_id=database["pan_id"], initialize=True, debug_monitor=False)
        self.fp = FrameProvider()
        self.fp.set_security_frame_counter(database["frame_counter"])
        self.fp.set_extended_source(database["extended_source_addr"])
        self.fp.set_nwk_key(database["network_key"])
        
        #link status and route request looper on a 5 second interval:
        self.spoofer = ZigbeeSpoofer(self.fp)
        self.beacon = ZigBeacon(self.fp)
        
    #@staticmethod
    def response_proc(self, packet: Packet, transaction_sequence: int) -> Tuple[bool, Packet]:
        if packet is not None and packet.src_addr == database["target_node"]:
            logging.info(f"{Fore.GREEN}<--- Packet: {packet.summary()}")
            if packet.haslayer(ZigbeeNWK) and packet.flags & 2 and packet.src_addr in database["nodes"]:
                logging.debug(f"network key: {database['network_key'].hex()}")
                decrypted_payload, success = CryptoUtils.zigbee_packet_decrypt(database['network_key'], packet, database["nodes"][packet.src_addr])
                if success:
                    if decrypted_payload.haslayer(ZigbeeClusterLibrary) and decrypted_payload.transaction_sequence == transaction_sequence:
                        logging.info(f"{Fore.YELLOW}decoded frame {decrypted_payload.summary()}")
                        return True, decrypted_payload
        return False, packet
    
    
    # Model learning-specific methods
    def default(self):
        return "invalid input provided"
        
    def pre(self):        
        logging.info("====  Preparation   ====")
        while self.get_device_state(database["target_node"]) == ERROR:
            logging.warning(f"{Fore.RED}Retrying to get device state")
            time.sleep(1)
        if self.get_device_state(database["target_node"]) != "ON":
            logging.debug("Turning on the device")
            self.set_device_state(database["target_node"], "ON")
        logging.info("====      Done      ====")
                
    def post(self):        
        logging.info("____Round Done______")
        pass
            
    def step(self, letter):
        requests = {
            "turn_on": {"method": self.set_device_state, "args": [database["target_node"], "ON"]},
            "turn_off": {"method": self.set_device_state, "args": [database["target_node"], "OFF"]},
            "toggle": {"method": self.set_device_state, "args": [database["target_node"], "TOGGLE"]},
            "get_state": {"method": self.get_device_state, "args": [database["target_node"]]},
        }
        
        request = requests.get(letter, {"method": self.default})
        output = request["method"](*request["args"])
        time.sleep(database["wait_time_in_between_steps"])
        return output
    
    # Device Control Functions
    def set_device_state(self, device_id: int, state: str):
        match state:
            case "ON":
                status = 0x1
            case "OFF":
                status = 0x0
            case _:
                status = 0x2
        write_attributes_frame, transaction_sequence = self.fp.zcl_on_off(0x0, database["pan_id"], device_id, status)
        logging.info(f"{Fore.BLUE}---> Packet: {write_attributes_frame.summary()}")
        response = Transceiver.send_and_receive(write_attributes_frame, self.response_proc, sleep_time=database["wait_time_for_packet_response"], transaction_sequence_number=transaction_sequence)
        if response:
            logging.info(f"{Fore.YELLOW}status: {response.getlayer(ZCLGeneralDefaultResponse).status}")
            return state
        return ERROR
        
    
    def get_device_state(self, device_id: int):
        read_attributes_frame, transaction_sequence = self.fp.zcl_read_attributes(0x0, database["pan_id"], device_id)
        logging.info(f"{Fore.BLUE}---> Packet: {read_attributes_frame.summary()}")
        response = Transceiver.send_and_receive(read_attributes_frame, self.response_proc, sleep_time=database["wait_time_for_packet_response"], transaction_sequence_number=transaction_sequence)
        if response:
            logging.info(f"{Fore.YELLOW}attribute value: {response.getlayer(ZCLGeneralReadAttributesResponse).read_attribute_status_record[0].attribute_value}")
            match response.getlayer(ZCLGeneralReadAttributesResponse).read_attribute_status_record[0].attribute_value:
                case b'\x00':
                    return "OFF"
                case b'\x01':
                    return "ON"
        return ERROR

if __name__ == '__main__':
        
    alphabet = ["turn_on", "turn_off", "get_state"]#, "toggle"]
    sul = ZigbeeInjectionClient()
        # Usage example for Zigbee2MQTT client

    eq_oracle = StatePrefixEqOracle(alphabet, sul, walks_per_state=2, walk_len=2)
    #eq_oracle = RandomWalkEqOracle(alphabet, sul, num_steps=5)

    # run the learning algorithm
    # internal caching is disabled, since we require an error handling for possible non-deterministic behavior
    learned_model = run_Lstar(alphabet, sul, eq_oracle, automaton_type='mealy',cache_and_non_det_check=True, print_level=3)
    #learned_model = run_KV(alphabet, sul, eq_oracle, automaton_type='mealy', cache_and_non_det_check=True, print_level=3)
    
    #stop the spoofing thread
    # visualize the automaton
    visualize_automaton(learned_model, path="learnedModel.pdf", file_type='pdf')
    sul.spoofer.done = True
    sul.beacon.done = True