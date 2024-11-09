from scapy.compat import raw
from scapy.all import *
from scapy.layers.dot15d4 import Dot15d4, Dot15d4Beacon, Dot15d4FCS, Dot15d4Data, Dot15d4Ack
from scapy.layers.zigbee import ZigBeeBeacon, ZigbeeNWK, ZigbeeSecurityHeader, ZigbeeAppDataPayload, ZigbeeClusterLibrary, ZCLGeneralReadAttributes, ZCLGeneralReadAttributesResponse, ZCLReadAttributeStatusRecord
from scapy.layers.zigbee import *
from random import randint
import logging
from crypto import CryptoUtils
# Now, all logging calls in the application will output to the command line
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()],
)

NWK_KEY = bytes.fromhex("31701f12dd93150ec4efce97e381ef06")
TI_EXTENDED_SOURCE = bytes.fromhex("00:12:4b:00:1c:dd:27:3d".replace(":", ""))
PHILIPS_TARGET = bytes.fromhex("00:17:88:01:0b:57:c9:f2".replace(":", ""))
'''
Ack frame
<Dot15d4FCS  fcf_reserved_1=0 fcf_panidcompress=False fcf_ackreq=False fcf_pending=False fcf_security=False fcf_frametype=Ack fcf_srcaddrmode=None fcf_framever=0 fcf_destaddrmode=None fcf_reserved_2=0 seqnum=223 fcs=0x9bc2 |>

'''
def ack_frame(self, seq: int) -> Packet:
    frame = Dot15d4FCS(seqnum=seq, fcf_frametype='Ack', fcf_panidcompress=False, fcf_ackreq=False, fcf_srcaddrmode='None', fcf_destaddrmode='None')
    return frame

'''
ZCL turn on/off
<Dot15d4FCS  fcf_reserved_1=0 fcf_panidcompress=True fcf_ackreq=True fcf_pending=False fcf_security=False fcf_frametype=Data fcf_srcaddrmode=Short fcf_framever=0 fcf_destaddrmode=Short fcf_reserved_2=0 seqnum=223 fcs=0xc378 |<Dot15d4Data  dest_panid=0x1a62 dest_addr=0x92e0 src_addr=0x0 |<ZigbeeNWK  discover_route=1 proto_version=2 frametype=data flags=security destination=0x92e0 source=0x0 radius=30 seqnum=33 |<ZigbeeSecurityHeader  reserved1= extended_nonce=1 key_type=network_key nwk_seclevel=None fc=0x142b8 source=00:12:4b:00:1c:dd:27:3d key_seqnum=0 data=<ZigbeeAppDataPayload  frame_control= delivery_mode=unicast aps_frametype=data dst_endpoint=11 cluster=0x6 profile=HA_Home_Automation src_endpoint=1 counter=164 |<ZigbeeClusterLibrary  reserved=0 disable_default_response=0 command_direction=0 manufacturer_specific=0 zcl_frametype=cluster-specific transaction_sequence=11 command_identifier=read_attributes |>> |>>>>
'''
def zcl_on_off(self, src_pan_id: bytes, src_addr: bytes, dst_pan_id: bytes, dst_addr: bytes, seq: int, on: bool) -> Packet:
    frame = Dot15d4FCS(seqnum=seq, fcf_frametype='Data', fcf_panidcompress=True, fcf_ackreq=True, fcf_srcaddrmode='Short', fcf_destaddrmode='Short')\
            /Dot15d4Data(dest_panid=dst_pan_id, dest_addr=dst_addr, src_addr=src_addr)\
            /ZigbeeNWK(discover_route=1, proto_version=2, frametype='data', flags='security', destination=dst_addr, source=src_addr, radius=30, seqnum=randint(0, 255))\
            /ZigbeeSecurityHeader(reserved1=0, extended_nonce=1, key_type='network_key', nwk_seclevel=None, fc=0x142b8, source=src_addr, key_seqnum=0)\
            /ZigbeeAppDataPayload(frame_control='', delivery_mode='unicast', aps_frametype='data', dst_endpoint=11, cluster=0x6, profile='HA_Home_Automation', src_endpoint=1, counter=randint(0, 255))\
            /ZigbeeClusterLibrary(reserved=0, disable_default_response=0, command_direction=0, manufacturer_specific=0, zcl_frametype='cluster-specific', transaction_sequence=11, command_identifier='read_attributes')
    return frame

'''
ZCLReadAttributes, onoff
<Dot15d4FCS  fcf_reserved_1=0 fcf_panidcompress=True fcf_ackreq=True fcf_pending=False fcf_security=False fcf_frametype=Data fcf_srcaddrmode=Short fcf_framever=0 fcf_destaddrmode=Short fcf_reserved_2=0 seqnum=63 fcs=0x42b3 |<Dot15d4Data  dest_panid=0x1a62 dest_addr=0x92e0 src_addr=0x0 |<ZigbeeNWK  discover_route=1 proto_version=2 frametype=data flags=security destination=0x92e0 source=0x0 radius=30 seqnum=134 |<ZigbeeSecurityHeader  reserved1= extended_nonce=1 key_type=network_key nwk_seclevel=None fc=0x14218 source=00:12:4b:00:1c:dd:27:3d key_seqnum=0 data=<ZigbeeAppDataPayload  frame_control= delivery_mode=unicast aps_frametype=data dst_endpoint=11 cluster=0x6 profile=HA_Home_Automation src_endpoint=1 counter=100 |<ZigbeeClusterLibrary  reserved=0 disable_default_response=1 command_direction=0 manufacturer_specific=0 zcl_frametype=profile-wide transaction_sequence=9 command_identifier=read_attributes |<ZCLGeneralReadAttributes  attribute_identifiers=[0x0] |>>> |>>>>
'''
def zcl_read_attributes(self, src_pan_id: bytes, src_addr: bytes, dst_pan_id: bytes, dst_addr: bytes, seq: int) -> Packet:
    frame = Dot15d4FCS(seqnum=seq, fcf_frametype='Data', fcf_panidcompress=True, fcf_ackreq=True, fcf_srcaddrmode='Short', fcf_destaddrmode='Short')\
            /Dot15d4Data(dest_panid=dst_pan_id, dest_addr=dst_addr, src_addr=src_addr)\
            /ZigbeeNWK(discover_route=1, proto_version=2, frametype='data', flags='security', destination=dst_addr, source=src_addr, radius=30, seqnum=randint(0, 255))\
            /ZigbeeSecurityHeader(reserved1=0, extended_nonce=1, key_type='network_key', nwk_seclevel=None, fc=0x14218, source=TI_EXTENDED_SOURCE, key_seqnum=0)\
            /ZigbeeAppDataPayload(frame_control='', delivery_mode='unicast', aps_frametype='data', dst_endpoint=11, cluster=0x6, profile='HA_Home_Automation', src_endpoint=1, counter=randint(0, 255))\
            /ZigbeeClusterLibrary(reserved=0, disable_default_response=1, command_direction=0, manufacturer_specific=0, zcl_frametype='profile-wide', transaction_sequence=9, command_identifier='read_attributes')\
            /ZCLGeneralReadAttributes(attribute_identifiers=[0x0])
    return frame

'''
ZCLReadAttributesResponse
[ decrypted=True, timestamp=1456477249, channel=11, rssi=-39, is_fcs_valid=True, lqi=216 ]
<Dot15d4FCS  fcf_reserved_1=0 fcf_panidcompress=True fcf_ackreq=True fcf_pending=False fcf_security=False fcf_frametype=Data fcf_srcaddrmode=Short fcf_framever=0 fcf_destaddrmode=Short fcf_reserved_2=0 seqnum=18 fcs=0x966c |<Dot15d4Data  dest_panid=0x1a62 dest_addr=0x0 src_addr=0x92e0 |<ZigbeeNWK  discover_route=1 proto_version=2 frametype=data flags=security destination=0x0 source=0x92e0 radius=30 seqnum=244 |<ZigbeeSecurityHeader  reserved1= extended_nonce=1 key_type=network_key nwk_seclevel=None fc=0x79d018 source=00:17:88:01:0b:57:c9:f2 key_seqnum=0 data=<ZigbeeAppDataPayload  frame_control= delivery_mode=unicast aps_frametype=data dst_endpoint=1 cluster=0x6 profile=HA_Home_Automation src_endpoint=11 counter=203 |<ZigbeeClusterLibrary  reserved=0 disable_default_response=1 command_direction=1 manufacturer_specific=0 zcl_frametype=profile-wide transaction_sequence=9 command_identifier=read_attributes_response |<ZCLGeneralReadAttributesResponse  read_attribute_status_record=[<ZCLReadAttributeStatusRecord  attribute_identifier=0x0 status=SUCCESS attribute_data_type=boolean attribute_value='\x01' |>] |>>> |>>>>
'''
def zcl_read_attributes_response(self, src_pan_id: bytes, src_addr: bytes, dst_pan_id: bytes, dst_addr: bytes, seq: int) -> Packet:
    pass

def beacon_allowing_join(self, src_pan_id: bytes, epan_id: bytes, seq: int) -> Packet:
    frame = Dot15d4FCS(seqnum=seq, fcf_frametype='Beacon', fcf_panidcompress=False, fcf_ackreq=False, fcf_srcaddrmode='Short', fcf_destaddrmode='None')\
            /Dot15d4Beacon(src_panid=src_pan_id, src_addr=0x0000, sf_assocpermit=True, sf_pancoord=True, gts_spec_permit=False, pa_num_long=0, pa_num_short=0)\
            /ZigBeeBeacon(proto_id=0, stack_profile=2, end_device_capacity=1, router_capacity=1, nwkc_protocol_version=0x2, device_depth=0x0, extended_pan_id=epan_id, tx_offset=0xffffff)
    return frame

if __name__ == '__main__':
    
    conf.dot15d4_protocol = 'zigbee'
    #zcl_read_attributes(None, 0x1a62, 0x92e0, 0x1a62, 0x92e0, 63).show()
    #zcl_on_off(None, 0x1a62, 0x92e0, 0x1a62, 0x92e0, 223, True).show()
    ztest_frame = zcl_on_off(None, 0x92e0, 0x0, 0x1a62, 0x92e0, 223, True)
    data = CryptoUtils.zigbee_packet_encrypt(NWK_KEY, ztest_frame, b'\x01', TI_EXTENDED_SOURCE)
    wrpcap('test_frame.pcap', data)
    data.show()
    #ack_frame(None, 223).show()
    frames = rdpcap('off.pcap')
    for frame in frames[1:2]:
        if not frame.fcf_frametype == 2:
            if frame.haslayer(ZigbeeSecurityHeader):
                print("Decrypting frame...")
                print(frame.show())
                extended_source = frame.getlayer(ZigbeeSecurityHeader).source.to_bytes(8, 'big')
                print(extended_source.hex(':'))
                data, status = CryptoUtils.zigbee_packet_decrypt(NWK_KEY, frame, extended_source)
                if(status):
                    if data.haslayer(ZigbeeNWKCommandPayload):
                        print("skipping...")
                    else:
                        print(data.show())
                else:
                    print("Failed to decrypt")
            #print(frame.summary())
        #else:
        #    print(frame.summary())
    