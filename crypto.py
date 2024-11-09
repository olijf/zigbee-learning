from typing import Tuple
from Crypto.Cipher import AES #pycryptodome
from Crypto.Util import Counter
import struct

from scapy.layers.dot15d4 import *
from scapy.layers.zigbee import *
import struct

'''
From Zigdiggity by BishopFox
zigdiggity/crypto/utils.py

https://github.com/BishopFox/zigdiggity/blob/master/zigdiggity/crypto/utils.py

student project of TUE:
https://github.com/matthijs2704/2ic80-zigbee-attacktool/blob/954eba944a58216a779d3cfc7ccc7623da53dc1b/zigdiggity/crypto/utils.py

'''

conf.dot15d4_protocol = 'zigbee'
DEFAULT_TRANSPORT_KEY = b'ZigBeeAlliance09'

ZLL_MASTER_KEY = b'9F 55 95 F1 02 57 C8 A4 69 CB F4 2B C9 3F EE 31'
'''https://www.reddit.com/r/hackernews/comments/2zzt2x/zigbee_light_link_master_key/
original message deleted, but the key is still there

https://web.archive.org/web/20150323125409/https://twitter.com/MayaZigBee/status/579723961661022209


'''
BLOCK_SIZE = 16
MIC_SIZE = 4

class CryptoUtils:
    @staticmethod
    def block_xor(block1, block2) -> bytes:
        return bytes([_a ^ _b for _a, _b in zip(block1, block2)])

    @staticmethod
    def zigbee_sec_hash(aInput) -> bytes:
        # construct the whole input
        zero_padding_length = (((BLOCK_SIZE-2) - len(aInput) % BLOCK_SIZE) - 1) % BLOCK_SIZE
        padded_input = aInput + b'\x80' + b'\x00' * zero_padding_length + struct.pack(">H", 8*len(aInput))
        number_of_blocks = int(len(padded_input)/BLOCK_SIZE)
        key = b'\x00'*BLOCK_SIZE
        for i in range(number_of_blocks):
            cipher = AES.new(key, AES.MODE_ECB)
            ciphertext = cipher.encrypt(padded_input[BLOCK_SIZE*i:BLOCK_SIZE*(i+1)])
            key = CryptoUtils.block_xor(ciphertext, padded_input[BLOCK_SIZE*i:BLOCK_SIZE*(i+1)])
        return key

    @staticmethod
    def zigbee_sec_key_hash(key, aInput) -> bytes:
        ipad = b'\x36'*BLOCK_SIZE
        opad = b'\x5c'*BLOCK_SIZE
        key_xor_ipad = CryptoUtils.block_xor(key, ipad)
        key_xor_opad = CryptoUtils.block_xor(key, opad)
        return CryptoUtils.zigbee_sec_hash(key_xor_opad + CryptoUtils.zigbee_sec_hash(key_xor_ipad + aInput))

    @staticmethod
    def zigbee_trans_key(key):
        return CryptoUtils.zigbee_sec_key_hash(key, b'\x00')

    @staticmethod
    def zigbee_decrypt(key, nonce, extra_data, ciphertext, mic):

        cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=4)
        cipher.update(extra_data)
        text = cipher.decrypt(ciphertext)
        try:
                cipher.verify(mic)
                mic_valid = True
        except ValueError:
                mic_valid = False
        return (text, mic_valid)

    @staticmethod
    def zigbee_encrypt(key, nonce, extra_data, text):
    
        cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=4)
        cipher.update(extra_data)

        ciphertext, mic = cipher.encrypt_and_digest(text)

        return (ciphertext, mic)

    @staticmethod
    def zigbee_get_packet_nonce(aPacket: Packet, extended_source: bytes) -> bytes:

        nonce = struct.pack('Q',*struct.unpack('>Q', extended_source)) + struct.pack('I', aPacket[ZigbeeSecurityHeader].fc) + struct.pack('B', bytes(aPacket[ZigbeeSecurityHeader])[0])
        return nonce

    @staticmethod
    def zigbee_get_packet_header(aPacket: Packet) -> bytes:
    
        ciphertext = aPacket[ZigbeeSecurityHeader].data
        mic = aPacket[ZigbeeSecurityHeader].mic
        data_len = len(ciphertext) + len(mic)
        
        if ZigbeeAppDataPayload in aPacket:
                if data_len > 0:
                        header = bytes(aPacket[ZigbeeAppDataPayload])[:-data_len]
                else:
                        header = bytes(aPacket[ZigbeeAppDataPayload])
        else:
                if data_len > 0:
                        header = bytes(aPacket[ZigbeeNWK])[:-data_len]
                else:
                        header = bytes(aPacket[ZigbeeNWK])
  
        return header

    @staticmethod
    def zigbee_packet_decrypt(key, aPacket: Packet, extended_source: bytes) -> Tuple[Packet, bool]:
    
        new_packet = aPacket.copy()
        new_packet[ZigbeeSecurityHeader].nwk_seclevel = 5
        if aPacket.haslayer(Dot15d4FCS):
            new_packet = Dot15d4FCS(bytes(new_packet))
        else:
            new_packet = Dot15d4(bytes(new_packet))

        ciphertext = new_packet[ZigbeeSecurityHeader].data
        mic = new_packet[ZigbeeSecurityHeader].mic

        header = CryptoUtils.zigbee_get_packet_header(new_packet)
        nonce = CryptoUtils.zigbee_get_packet_nonce(new_packet, extended_source)
        
        payload, mic_valid =  CryptoUtils.zigbee_decrypt(key, nonce, header, ciphertext, mic)
        frametype = new_packet[ZigbeeNWK].frametype
        if frametype == 0 and mic_valid:
                payload = ZigbeeAppDataPayload(payload)
        elif frametype == 1 and mic_valid:
                payload = ZigbeeNWKCommandPayload(payload)
        
        return payload, mic_valid

    @staticmethod
    def zigbee_packet_encrypt(key, unencrypted_frame_part: Packet, payload: bytes, extended_source: bytes) -> Dot15d4:
    
        if not ZigbeeSecurityHeader in unencrypted_frame_part:
            return b''

        new_packet = unencrypted_frame_part.copy()
        new_packet[ZigbeeSecurityHeader].nwk_seclevel = 5
        
        header = CryptoUtils.zigbee_get_packet_header(new_packet)
        nonce = CryptoUtils.zigbee_get_packet_nonce(new_packet, extended_source)

        data, mic = CryptoUtils.zigbee_encrypt(key, nonce, header, payload)

        new_packet.data = data
        new_packet.mic = mic

        new_packet.nwk_seclevel = 0
        if unencrypted_frame_part.haslayer(Dot15d4FCS):
            return Dot15d4FCS(bytes(new_packet))
        return Dot15d4(bytes(new_packet))

if __name__ == '__main__':
    # Example usage of the CryptoUtils
    from scapy.all import rdpcap
    key = bytes.fromhex('6be7b689289b1b9c353a38f8b54ffd06')
    frames = rdpcap('factory_reset_met_behulp_van_scapy.pcapng')
    frames[11].show()
    extended_source = frames[11].ext_src.to_bytes(8, 'big')
    print(f"extended_source = {extended_source.hex(':')}")
    print(f"key = {key.hex(' ')}")
    payload, succes = CryptoUtils.zigbee_packet_decrypt(key, frames[11], extended_source)
    if succes:
        print('Decrypted packet:')
        payload.show()
        print(payload)
    else:
        print('Failed to decrypt packet')