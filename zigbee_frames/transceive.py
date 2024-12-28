import time
from typing import Callable, Tuple
from scapy.all import Packet, conf, sendp, AsyncSniffer, sniff
#from scapy.layers.lightlinkzbee import *
from scapy.layers.zigbee import *
from util.wpan_interface import Phy
from util.crypto import CryptoUtils
import logging
from threading import Event

conf.dot15d4_protocol = 'zigbee'
conf.debug_match = True
#conf.verb = 0
NWK_KEY = bytes.fromhex("31701f12dd93150ec4efce97e381ef06")

PHILIPS_TARGET = bytes.fromhex("00:17:88:01:0b:57:c9:f2".replace(":", ""))
return_answer = None

class Transceiver:
    @staticmethod
    def send_and_receive(
        frame: Packet,
        process_response_func: Callable[[Packet, int], Tuple[bool, Packet]]=lambda x, _: (x.haslayer(ZigbeeAppDataPayload), x),
        chan: int=11,
        phy: Phy=None,
        iface: str = "wpan0",
        sleep_time: float = 1.0,
        transaction_sequence_number: int = 0
    ) -> Tuple[Packet]:
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
            logging.debug(f"Sending on channel {chan}")
        
        logging.debug(f"Sending packet {frame.summary()} with frame.fc={frame.fc}")
        
        global return_answer
        return_answer = None
        event = Event()
        
        if not sleep_time < 0.1:
            def process_packet(packet):
                expected_frame = Dot15d4(packet.do_build())
                answers, decoded = process_response_func(expected_frame, transaction_sequence_number)
                if answers:
                    global return_answer
                    return_answer = decoded
                    event.set()
                
            sniffer = AsyncSniffer(iface=iface, prn=process_packet, store=False)
            sniffer.start()
        
        sendp(frame, iface=iface, verbose=0)  # can't use srp because we are not using ethernet
        
        if not sleep_time < 0.1:
            # Wait for the event or timeout
            if event.wait(timeout=sleep_time):
                sniffer.stop()
                return return_answer
            sniffer.stop()
            
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
        logging.debug(f"Receiving on channel {chan}")
        
        return_answer = None
        
        sniff(iface=iface, prn=lambda x: Dot15d4(x.do_build()).summary(), store=False, timeout=15)
        
        return return_answer
    
