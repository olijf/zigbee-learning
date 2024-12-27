import time
from typing import Callable, Tuple
from scapy.all import Packet, conf, sendp, AsyncSniffer, sniff
#from scapy.layers.lightlinkzbee import *
from scapy.layers.zigbee import *
from util.wpan_interface import Phy
from util.crypto import CryptoUtils


conf.dot15d4_protocol = 'zigbee'
conf.debug_match = True
NWK_KEY = bytes.fromhex("31701f12dd93150ec4efce97e381ef06")

PHILIPS_TARGET = bytes.fromhex("00:17:88:01:0b:57:c9:f2".replace(":", ""))

class Transceiver:
    @staticmethod
    def process_sniffer_results(results, process_response_func: Callable[[Packet], bool]) -> Packet:
        """
        Process the results from the sniffer.
        
        :param results: List of packets captured by the sniffer
        :param process_response_func: Function to process the received packet
        :return: The first packet that matches the criteria defined by process_response_func, if any
        """
        if len(results) > 0:
            print("##### Received packet:")
            for packet in results:
                expected_frame = Dot15d4FCS(packet.do_build())  # have to do this this way otherwise scapy thinks it's an ethernet packet
                expected_frame.summary()
                if expected_frame.haslayer(ZigbeeSecurityHeader):
                    decrypted, status = CryptoUtils.zigbee_packet_decrypt(NWK_KEY, expected_frame, PHILIPS_TARGET)
                    if status:
                        decrypted.show()
                if process_response_func(expected_frame):
                    return expected_frame
        return None

    @staticmethod
    def send_and_receive(
        frame: Packet,
        process_response_func: Callable[[Packet], bool]=lambda x: x.haslayer(ZigbeeAppDataPayload),
        chan: int=11,
        phy: Phy=None,
        iface: str = "wpan0",
        sleep_time: float = 1.0
    ) -> Tuple[Packet, int]:
        """
        Generic function to send a packet and receive a response.
        
        :param create_packet_func: Function to create the packet to be sent
        :param process_response_func: Function to process the received packet
        :param chan: Channel number
        :param phy: PHY name
        :param iface: Network interface to use
        :param sleep_time: Time to wait for responses
        :return: received packet (if any)
        """
        if phy:
            phy.switch_channel(chan)
        time.sleep(0.1)
        print(f"Sending on channel {chan}")
        
        print(f"Sending packet {frame} with frame.fc={frame.fc}")
        
        return_answer = None
        
        if not sleep_time < 0.1:
            sniffer = AsyncSniffer(iface=iface)
            sniffer.start()
        
        sendp(frame, iface=iface)  # can't use srp because we are not using ethernet
        time.sleep(sleep_time)  # sleep to give devices time to respond
        
        if not sleep_time < 0.1:
            sniffer.stop()
            return_answer = Transceiver.process_sniffer_results(sniffer.results, process_response_func)
        
        return return_answer
    
    
    """TODO: get this working with WPAN, somehow frames are always interpreted as ethernet by SCAPY"""
    @staticmethod
    def receive(chan: int=11, phy: Phy=None, iface: str = "wpan0") -> Tuple[Packet, int]:
        """
        Generic function to receive a packet.
        
        :param process_response_func: Function to process the received packet
        :param chan: Channel number
        :param phy: PHY name
        :param iface: Network interface to use
        :param sleep_time: Time to wait for responses
        :return: received packet (if any)
        """
        if phy:
            phy.switch_channel(chan)
        time.sleep(0.1)
        print(f"Receiving on channel {chan}")
        
        return_answer = None
        
        sniff(iface=iface, prn=lambda x: Dot15d4FCS(x.do_build()).summary(), store=False, timeout=15)
        
        return return_answer
    
