from random import randint
from zigbee_frames.transceive import Transceiver
from util.wpan_interface import Phy
from scapy.all import conf, CacheInstance, Packet, sniff
from scapy.layers.dot15d4 import Dot15d4, Dot15d4Beacon, Dot15d4FCS, Dot15d4Data, Dot15d4Ack
from scapy.layers.zigbee import ZigBeeBeacon, ZigbeeNWK, ZigbeeSecurityHeader, ZigbeeAppDataPayload, ZigbeeClusterLibrary, ZCLGeneralReadAttributes, ZCLGeneralReadAttributesResponse, ZCLReadAttributeStatusRecord, ZigbeeNWKCommandPayload
from util.crypto import CryptoUtils

NWK_KEY = bytes.fromhex("31701f12dd93150ec4efce97e381ef06")
TI_EXTENDED_SOURCE = bytes.fromhex("00:12:4b:00:1c:dd:27:3d".replace(":", ""))
PHILIPS_TARGET = bytes.fromhex("00:17:88:01:0b:57:c9:f2".replace(":", ""))
frame_counter = randint(0, 255)

def zcl_on_off(src_addr: bytes, dst_pan_id: bytes, dst_addr: bytes, seq: int, on: bool) -> Packet:
    extended_source = int.from_bytes(TI_EXTENDED_SOURCE, 'big')
    if on: cmd_identifier = 0x01
    else: cmd_identifier = 0x02
    #data = CryptoUtils.zigbee_packet_encrypt(NWK_KEY, ztest_frame, b'\x01', TI_EXTENDED_SOURCE)
    unencrypted_part = dot15d4_data_header(src_addr, dst_pan_id, dst_addr, seq)\
            /zbee_nwk_header(src_addr, dst_addr, seq)\
            /zbee_security_header(extended_source, seq)
    frame_payload = ZigbeeAppDataPayload(frame_control='', delivery_mode='unicast', aps_frametype='data', dst_endpoint=11, cluster=0x6, profile='HA_Home_Automation', src_endpoint=1, counter=seq)\
            /ZigbeeClusterLibrary(reserved=0, disable_default_response=0, command_direction=0, manufacturer_specific=0, zcl_frametype='cluster-specific', transaction_sequence=seq, command_identifier=cmd_identifier)
    return CryptoUtils.zigbee_packet_encrypt(NWK_KEY, unencrypted_part, bytes(frame_payload), extended_source.to_bytes(8, 'big'))
    

def dot15d4_data_header(src_addr, dst_pan_id, dst_addr, seq):
    return Dot15d4(seqnum=seq, fcf_frametype='Data', fcf_panidcompress=True, fcf_ackreq=True, fcf_srcaddrmode='Short', fcf_destaddrmode='Short')\
            /Dot15d4Data(dest_panid=dst_pan_id, dest_addr=dst_addr, src_addr=src_addr)

def zbee_nwk_header(source, destination, nwk_seq, extended_source=None, ftype='data'):
    frame = ZigbeeNWK(discover_route=1, proto_version=2, frametype=ftype, flags='security', destination=destination, source=source, radius=30, seqnum=nwk_seq)
    if extended_source is not None:
        frame.ext_src = extended_source
        frame.flags += 'extended_src'
    return frame

def zbee_security_header(extended_source, frame_counter):
    return ZigbeeSecurityHeader(reserved1=0, extended_nonce=1, key_type='network_key', nwk_seclevel=None, fc=frame_counter, source=extended_source, key_seqnum=0)

def zcl_read_attributes(src_addr: bytes, dst_pan_id: bytes, dst_addr: bytes, seq: int) -> Packet:
    extended_source = int.from_bytes(TI_EXTENDED_SOURCE, 'big')
    unencrypted_part = dot15d4_data_header(src_addr, dst_pan_id, dst_addr, seq)\
            /zbee_nwk_header(src_addr, dst_addr, seq)\
            /zbee_security_header(extended_source, seq)
    frame_payload = ZigbeeAppDataPayload(frame_control='', delivery_mode='unicast', aps_frametype='data', dst_endpoint=11, cluster=0x6, profile='HA_Home_Automation', src_endpoint=1, counter=seq)\
            /ZigbeeClusterLibrary(reserved=0, disable_default_response=1, command_direction=0, manufacturer_specific=0, zcl_frametype='profile-wide', transaction_sequence=seq, command_identifier='read_attributes')\
            /ZCLGeneralReadAttributes(attribute_identifiers=[0x0])
    return  CryptoUtils.zigbee_packet_encrypt(NWK_KEY, unencrypted_part, bytes(frame_payload), extended_source.to_bytes(8, 'big'))

def many_to_one_route_request(nwk_dst: int, seq: int) -> Packet:
    extended_source = int.from_bytes(TI_EXTENDED_SOURCE, 'big')
    unencrypted_part = dot15d4_data_header(0x0000, 0xffff, seq)\
            /zbee_nwk_header(0x0000, nwk_dst, seq, extended_source, 'command')\
            /zbee_security_header(extended_source, seq)
    frame_payload = ZigbeeNWKCommandPayload(cmd_identifier=1, multicast=0, dest_addr_bit=0, many_to_one=2, destination_address=nwk_dst, path_cost=0)
    return  CryptoUtils.zigbee_packet_encrypt(NWK_KEY, unencrypted_part, bytes(frame_payload), extended_source.to_bytes(8, 'big'))

def gather_nodes_and_extended_source(iface: str) -> dict:
    #sniff some traffic to build up a list of nodes:
    dict_of_nodes = {}
    def add_node(node: Dot15d4FCS):
        #node.show()
        if node.src_addr not in dict_of_nodes:
            dict_of_nodes[node.src_addr] = 0
            print(f"new node found: {node.src_addr:04x}")
        if dict_of_nodes[node.src_addr] == 0 and node.haslayer(ZigbeeNWK) and node.flags == 'security+extended_src':
            dict_of_nodes[node.src_addr] = node.ext_src
            print(f"extended source found: {node.ext_src:016x}")

    sniff(iface=iface, prn=lambda x: add_node(Dot15d4FCS(x.do_build())), store=False, timeout=10)
    return dict_of_nodes

def find_counters(iface: str, nodes: dict):
    #sniff some traffic to find the frame counters of the nodes:
    def find_counter(node: Dot15d4FCS):
        if node.src_addr in nodes and node.flags == 'security+extended_src':
            print(f"node {node.src_addr:04x} has frame counter {node.fc}")

    sniff(iface=iface, prn=lambda x: find_counter(Dot15d4FCS(x.do_build())), store=False, timeout=10)

if __name__ == '__main__':
    #from util.wpan_interface import Phy
    
    source_addr = bytes.fromhex("00:12:4b:00:1c:dd:27:3d".replace(":", ""))
    phy=Phy(int.from_bytes(source_addr), initial_channel=11, initialize=False, debug_monitor=False)
    
    dict_of_nodes = gather_nodes_and_extended_source("wpan0")

    print("List of nodes:")
    for node in dict_of_nodes.keys():
        print(f"node {node:04x}, extended source: {dict_of_nodes[node]:016x}")
        
    find_counters("wpan0", dict_of_nodes)
    """
    while True:
        Transceiver.send_and_receive(zcl_read_attributes(0x0, 0x1a62, 0x2308, frame_counter))
        frame_counter = (frame_counter + 1) % 256
        Transceiver.send_and_receive(many_to_one_route_request(0xfffd, frame_counter))
        frame_counter = (frame_counter + 1) % 256
        """