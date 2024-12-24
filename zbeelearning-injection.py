from scapy.compat import raw
import socket
from scapy.all import *
from scapy.layers.dot15d4 import Dot15d4, Dot15d4Beacon, Dot15d4FCS, Dot15d4Data, Dot15d4Ack
from scapy.layers.zigbee import ZigBeeBeacon, ZigbeeNWK, ZigbeeSecurityHeader, ZigbeeAppDataPayload, ZigbeeClusterLibrary, ZCLGeneralReadAttributes, ZCLGeneralReadAttributesResponse, ZCLReadAttributeStatusRecord
from scapy.layers.zigbee import *
from random import randint
import logging
from util.crypto import CryptoUtils
# Now, all logging calls in the application will output to the command line
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()],
)

NWK_KEY = bytes.fromhex("31701f12dd93150ec4efce97e381ef06")
TI_EXTENDED_SOURCE = bytes.fromhex("00:12:4b:00:1c:dd:27:3d".replace(":", ""))
PHILIPS_TARGET = bytes.fromhex("00:17:88:01:0b:57:c9:f2".replace(":", ""))
frame_counter = randint(0, 255)
'''
Ack frame
<Dot15d4FCS  fcf_reserved_1=0 fcf_panidcompress=False fcf_ackreq=False fcf_pending=False fcf_security=False fcf_frametype=Ack fcf_srcaddrmode=None fcf_framever=0 fcf_destaddrmode=None fcf_reserved_2=0 seqnum=223 fcs=0x9bc2 |>

'''
def ack_frame(seq: int) -> Packet:
    frame = Dot15d4FCS(seqnum=seq, fcf_frametype='Ack', fcf_panidcompress=False, fcf_ackreq=False, fcf_srcaddrmode='None', fcf_destaddrmode='None')
    return frame

'''
ZCL turn on/off
<Dot15d4FCS  fcf_reserved_1=0 fcf_panidcompress=True fcf_ackreq=True fcf_pending=False fcf_security=False fcf_frametype=Data fcf_srcaddrmode=Short fcf_framever=0 fcf_destaddrmode=Short fcf_reserved_2=0 seqnum=223 fcs=0xc378 |<Dot15d4Data  dest_panid=0x1a62 dest_addr=0x92e0 src_addr=0x0 |<ZigbeeNWK  discover_route=1 proto_version=2 frametype=data flags=security destination=0x92e0 source=0x0 radius=30 seqnum=33 |<ZigbeeSecurityHeader  reserved1= extended_nonce=1 key_type=network_key nwk_seclevel=None fc=0x142b8 source=00:12:4b:00:1c:dd:27:3d key_seqnum=0 data=<ZigbeeAppDataPayload  frame_control= delivery_mode=unicast aps_frametype=data dst_endpoint=11 cluster=0x6 profile=HA_Home_Automation src_endpoint=1 counter=164 |<ZigbeeClusterLibrary  reserved=0 disable_default_response=0 command_direction=0 manufacturer_specific=0 zcl_frametype=cluster-specific transaction_sequence=11 command_identifier=read_attributes |>> |>>>>
'''
def zcl_on_off(src_addr: bytes, dst_pan_id: bytes, dst_addr: bytes, seq: int, on: bool) -> Packet:
    extended_source = int.from_bytes(TI_EXTENDED_SOURCE, 'big')
    if on: cmd_identifier = 0x01
    else: cmd_identifier = 0x02
    #data = CryptoUtils.zigbee_packet_encrypt(NWK_KEY, ztest_frame, b'\x01', TI_EXTENDED_SOURCE)
    unencrypted_part = dot15d4_data_header(src_addr, dst_pan_id, dst_addr, seq)\
            /zbee_nwk_header(src_addr, dst_addr, randint(0, 255))\
            /zbee_security_header(extended_source, randint(0, 255))
    frame_payload = ZigbeeAppDataPayload(frame_control='', delivery_mode='unicast', aps_frametype='data', dst_endpoint=11, cluster=0x6, profile='HA_Home_Automation', src_endpoint=1, counter=randint(0, 255))\
            /ZigbeeClusterLibrary(reserved=0, disable_default_response=0, command_direction=0, manufacturer_specific=0, zcl_frametype='cluster-specific', transaction_sequence=randint(0, 255), command_identifier=cmd_identifier)
    return CryptoUtils.zigbee_packet_encrypt(NWK_KEY, unencrypted_part, bytes(frame_payload), extended_source.to_bytes(8, 'big'))
    

def dot15d4_data_header(src_addr, dst_pan_id, dst_addr, seq):
    return Dot15d4FCS(seqnum=seq, fcf_frametype='Data', fcf_panidcompress=True, fcf_ackreq=True, fcf_srcaddrmode='Short', fcf_destaddrmode='Short')\
            /Dot15d4Data(dest_panid=dst_pan_id, dest_addr=dst_addr, src_addr=src_addr)

def zbee_nwk_header(source, destination, nwk_seq, extended_source=None):
    frame = ZigbeeNWK(discover_route=1, proto_version=2, frametype='data', flags='security', destination=destination, source=source, radius=30, seqnum=nwk_seq)
    if extended_source is not None:
        frame.ext_src = extended_source
    return frame

def zbee_security_header(extended_source, frame_counter):
    return ZigbeeSecurityHeader(reserved1=0, extended_nonce=1, key_type='network_key', nwk_seclevel=None, fc=frame_counter, source=extended_source, key_seqnum=0)
'''
ZCLReadAttributes, onoff
<Dot15d4FCS  fcf_reserved_1=0 fcf_panidcompress=True fcf_ackreq=True fcf_pending=False fcf_security=False fcf_frametype=Data fcf_srcaddrmode=Short fcf_framever=0 fcf_destaddrmode=Short fcf_reserved_2=0 seqnum=63 fcs=0x42b3 |<Dot15d4Data  dest_panid=0x1a62 dest_addr=0x92e0 src_addr=0x0 |<ZigbeeNWK  discover_route=1 proto_version=2 frametype=data flags=security destination=0x92e0 source=0x0 radius=30 seqnum=134 |<ZigbeeSecurityHeader  reserved1= extended_nonce=1 key_type=network_key nwk_seclevel=None fc=0x14218 source=00:12:4b:00:1c:dd:27:3d key_seqnum=0 data=<ZigbeeAppDataPayload  frame_control= delivery_mode=unicast aps_frametype=data dst_endpoint=11 cluster=0x6 profile=HA_Home_Automation src_endpoint=1 counter=100 |<ZigbeeClusterLibrary  reserved=0 disable_default_response=1 command_direction=0 manufacturer_specific=0 zcl_frametype=profile-wide transaction_sequence=9 command_identifier=read_attributes |<ZCLGeneralReadAttributes  attribute_identifiers=[0x0] |>>> |>>>>
'''
def zcl_read_attributes(src_addr: bytes, dst_pan_id: bytes, dst_addr: bytes, seq: int) -> Packet:
    extended_source = int.from_bytes(TI_EXTENDED_SOURCE, 'big')
    unencrypted_part = dot15d4_data_header(src_addr, dst_pan_id, dst_addr, seq)\
            /zbee_nwk_header(src_addr, dst_addr, randint(0, 255))\
            /zbee_security_header(extended_source, randint(0, 255))
    frame_payload = ZigbeeAppDataPayload(frame_control='', delivery_mode='unicast', aps_frametype='data', dst_endpoint=11, cluster=0x6, profile='HA_Home_Automation', src_endpoint=1, counter=randint(0, 255))\
            /ZigbeeClusterLibrary(reserved=0, disable_default_response=1, command_direction=0, manufacturer_specific=0, zcl_frametype='profile-wide', transaction_sequence=randint(0, 255), command_identifier='read_attributes')\
            /ZCLGeneralReadAttributes(attribute_identifiers=[0x0])
    return  CryptoUtils.zigbee_packet_encrypt(NWK_KEY, unencrypted_part, bytes(frame_payload), extended_source.to_bytes(8, 'big'))

'''
ZCLReadAttributesResponse
[ decrypted=True, timestamp=1456477249, channel=11, rssi=-39, is_fcs_valid=True, lqi=216 ]
<Dot15d4FCS  fcf_reserved_1=0 fcf_panidcompress=True fcf_ackreq=True fcf_pending=False fcf_security=False fcf_frametype=Data fcf_srcaddrmode=Short fcf_framever=0 fcf_destaddrmode=Short fcf_reserved_2=0 seqnum=18 fcs=0x966c |<Dot15d4Data  dest_panid=0x1a62 dest_addr=0x0 src_addr=0x92e0 |<ZigbeeNWK  discover_route=1 proto_version=2 frametype=data flags=security destination=0x0 source=0x92e0 radius=30 seqnum=244 |<ZigbeeSecurityHeader  reserved1= extended_nonce=1 key_type=network_key nwk_seclevel=None fc=0x79d018 source=00:17:88:01:0b:57:c9:f2 key_seqnum=0 data=<ZigbeeAppDataPayload  frame_control= delivery_mode=unicast aps_frametype=data dst_endpoint=1 cluster=0x6 profile=HA_Home_Automation src_endpoint=11 counter=203 |<ZigbeeClusterLibrary  reserved=0 disable_default_response=1 command_direction=1 manufacturer_specific=0 zcl_frametype=profile-wide transaction_sequence=9 command_identifier=read_attributes_response |<ZCLGeneralReadAttributesResponse  read_attribute_status_record=[<ZCLReadAttributeStatusRecord  attribute_identifier=0x0 status=SUCCESS attribute_data_type=boolean attribute_value='\x01' |>] |>>> |>>>>
'''
def zcl_read_attributes_response(self, src_pan_id: bytes, src_addr: bytes, dst_pan_id: bytes, dst_addr: bytes, seq: int) -> Packet:
    pass

if __name__ == '__main__':

    conf.dot15d4_protocol = 'zigbee'
    #zcl_read_attributes(0x92e0, 0x1a62, 0x92e0, 63).show()
    #zcl_on_off(0x92e0, 0x1a62, 0x92e0, 223, True).show()
    dest_addr = 0xDF6B
    ztest_frame = zcl_on_off(0x0, 0x1a62, 0x92e0, frame_counter, False)
    gnuradiosocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    host = '127.0.0.1'
    port = 52001
    gnuradiosocket.connect((host, port))
    gnuradiosocket.sendto(bytes(ztest_frame), (host, port))
    start_time = time.time()
    while True:
        data, addr = gnuradiosocket.recvfrom(1024)
        decoded_data = Dot15d4FCS(data)
        if decoded_data.fcf_ackreq == True and decoded_data.seqnum != frame_counter:
            print(f"Sending ack... {decoded_data.seqnum}")
            ack = ack_frame(decoded_data.seqnum)
            gnuradiosocket.sendto(bytes(ack), (host, port))
        # every 2nd second also transmit a new togle frame
        if time.time() - start_time > 2:
            start_time = time.time()
            
            frame_counter = randint(0, 255)
            ztest_frame = zcl_on_off(0x0, 0x1a62, 0x92e0, frame_counter, False)     
            gnuradiosocket.sendto(bytes(ztest_frame), (host, port))