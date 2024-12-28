from random import randint
from scapy.all import Packet
from scapy.layers.dot15d4 import Dot15d4, Dot15d4Data
from scapy.layers.zigbee import ZigbeeNWK, ZigbeeSecurityHeader, ZigbeeAppDataPayload, ZigbeeClusterLibrary, ZCLGeneralReadAttributes, ZCLGeneralReadAttributesResponse, ZCLReadAttributeStatusRecord, ZigbeeNWKCommandPayload
from util.crypto import CryptoUtils
import logging

class FrameProvider:
    def __init__(self):
        self._dot15d4_sequence_number = randint(0, 255)
        self._zigbee_nwk_sequence_number = randint(0, 255)
        self._zigbee_apl_counter = randint(0, 255)
        self._zigbee_zcl_sequence_number = randint(0, 255)
        self._zigbee_sec_frame_counter = randint(0, 255)
        src = 0xdeadbeefdeadbeef
        self._extended_source = src.to_bytes(8, 'big')
        self._nwk_key = bytes.fromhex("31701f12dd93150ec4efce97e381ef06")
    
    def set_security_frame_counter(self, counter: int):
        self._zigbee_sec_frame_counter = counter
        logging.debug(f"Frame counter set to {counter}")
    
    def set_extended_source(self, extended_source: bytes):
        self._extended_source = extended_source
        logging.debug(f"Extended source set to {extended_source.hex(':')}")
    
    def set_nwk_key(self, key: bytes):
        self._nwk_key = key
        logging.debug(f"Network key set to {key.hex()}")
        
    def dot15d4_data_header(self, src_addr, dst_pan_id, dst_addr, ackreq=True):
        self._dot15d4_sequence_number = (self._dot15d4_sequence_number + 1) % 256
        return Dot15d4(seqnum=self._dot15d4_sequence_number , fcf_frametype='Data', fcf_panidcompress=True, fcf_ackreq=ackreq, fcf_srcaddrmode='Short', fcf_destaddrmode='Short')\
                /Dot15d4Data(dest_panid=dst_pan_id, dest_addr=dst_addr, src_addr=src_addr)

    def zbee_nwk_header(self, source, destination, extended_source=None, ftype='data'):
        nwk_seq = self._zigbee_nwk_sequence_number
        self._zigbee_nwk_sequence_number = (self._zigbee_nwk_sequence_number + 1) % 256
        frame = ZigbeeNWK(discover_route=1, proto_version=2, frametype=ftype, flags='security', destination=destination, source=source, radius=30, seqnum=nwk_seq)
        if extended_source is not None:
            frame.ext_src = extended_source
            frame.flags += 'extended_src'
        return frame

    def zbee_security_header(self, extended_source):
        frame_counter = self._zigbee_sec_frame_counter
        self._zigbee_sec_frame_counter = (self._zigbee_sec_frame_counter + 1) % 0x80000000
        return ZigbeeSecurityHeader(reserved1=0, extended_nonce=1, key_type='network_key', nwk_seclevel=None, fc=frame_counter, source=extended_source, key_seqnum=0)

    def zcl_read_attributes(self, src_addr: bytes, dst_pan_id: bytes, dst_addr: bytes) -> Packet:
        extended_source = int.from_bytes(self._extended_source, 'big')
        unencrypted_part = self.dot15d4_data_header(src_addr, dst_pan_id, dst_addr)\
                /self.zbee_nwk_header(src_addr, dst_addr)\
                /self.zbee_security_header(extended_source)
        self._zigbee_apl_counter = (self._zigbee_apl_counter + 1) % 256
        self._zigbee_zcl_sequence_number = (self._zigbee_zcl_sequence_number + 1) % 256
        frame_payload = ZigbeeAppDataPayload(frame_control='', delivery_mode='unicast', aps_frametype='data', dst_endpoint=11, cluster=0x6, profile='HA_Home_Automation', src_endpoint=1, counter=self._zigbee_apl_counter)\
                /ZigbeeClusterLibrary(reserved=0, disable_default_response=1, command_direction=0, manufacturer_specific=0, zcl_frametype='profile-wide', transaction_sequence=self._zigbee_zcl_sequence_number, command_identifier='read_attributes')\
                /ZCLGeneralReadAttributes(attribute_identifiers=[0x0])
        return  CryptoUtils.zigbee_packet_encrypt(self._nwk_key, unencrypted_part, bytes(frame_payload), extended_source.to_bytes(8, 'big')), self._zigbee_zcl_sequence_number

    def many_to_one_route_request(self, nwk_dst: int, dst_pan_id: bytes) -> Packet:
        extended_source = int.from_bytes(self._extended_source , 'big')
        unencrypted_part = self.dot15d4_data_header(0x0000, dst_pan_id, 0xffff, ackreq=False)\
                /self.zbee_nwk_header(0x0000, nwk_dst, extended_source, 'command')\
                /self.zbee_security_header(extended_source)
        
        frame_payload = ZigbeeNWKCommandPayload(cmd_identifier=1, multicast=0, dest_addr_bit=0, many_to_one=2, destination_address=nwk_dst, path_cost=0)
        return  CryptoUtils.zigbee_packet_encrypt(self._nwk_key, unencrypted_part, bytes(frame_payload), extended_source.to_bytes(8, 'big'))

    def link_status(self, dst_pan_id: bytes) -> Packet:
        extended_source = int.from_bytes(self._extended_source , 'big')
        unencrypted_part = self.dot15d4_data_header(0x0000, dst_pan_id, 0xffff, ackreq=False)\
                /self.zbee_nwk_header(0x0000, 0xfffc, extended_source, 'command')\
                /self.zbee_security_header(extended_source)
        frame_payload = ZigbeeNWKCommandPayload(cmd_identifier=0x08, multicast=0, dest_addr_bit=0, many_to_one=0, destination_address=0xfffd, path_cost=0)
        return  CryptoUtils.zigbee_packet_encrypt(self._nwk_key, unencrypted_part, bytes(frame_payload), extended_source.to_bytes(8, 'big'))


    def zcl_on_off(self, src_addr: bytes, dst_pan_id: bytes, dst_addr: bytes, on: bool) -> Packet:
        extended_source = int.from_bytes(self._extended_source, 'big')
        if on: cmd_identifier = 0x01
        else: cmd_identifier = 0x02 #is toggle
        #data = CryptoUtils.zigbee_packet_encrypt(NWK_KEY, ztest_frame, b'\x01', TI_EXTENDED_SOURCE)
        unencrypted_part = self.dot15d4_data_header(src_addr, dst_pan_id, dst_addr)\
                /self.zbee_nwk_header(src_addr, dst_addr)\
                /self.zbee_security_header(extended_source)
        
        self._zigbee_apl_counter = (self._zigbee_apl_counter + 1) % 256
        self._zigbee_zcl_sequence_number = (self._zigbee_zcl_sequence_number + 1) % 256
        frame_payload = ZigbeeAppDataPayload(frame_control='', delivery_mode='unicast', aps_frametype='data', dst_endpoint=11, cluster=0x6, profile='HA_Home_Automation', src_endpoint=1, counter=self._zigbee_apl_counter)\
                /ZigbeeClusterLibrary(reserved=0, disable_default_response=0, command_direction=0, manufacturer_specific=0, zcl_frametype='cluster-specific', transaction_sequence=self._zigbee_zcl_sequence_number, command_identifier=cmd_identifier)
        return CryptoUtils.zigbee_packet_encrypt(self._nwk_key, unencrypted_part, bytes(frame_payload), extended_source.to_bytes(8, 'big')), self._zigbee_zcl_sequence_number
        