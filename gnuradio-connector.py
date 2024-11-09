import socket
import time
from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS, Dot15d4Data
from scapy.layers.zigbee import *
from scapy.all import fuzz, conf
from boofuzz import *
import boofuzz

class GnuradioConnector:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.connect((self.host, self.port))

    def send(self, data):
        self.sock.send(data)
        
    def sendto(self, data, addr):
        self.sock.sendto(data, addr)

    def recv(self, size):
        return self.sock.recv(size)

    def close(self):
        self.sock.close()
        

        
if __name__ == "__main__":
    gnuradio = GnuradioConnector("127.0.0.1", 52001)
    
    # / Dot15d4Data(dest_panid=0x1234, dest_addr=0x9234) / "Hello World"
    packet_base = Dot15d4FCS()
    packet_end = "Hello World"
    
    '''
    
    fuzzTest = Request(
        "olaf's Magic Fuzzing Request",
        children=(
            Simple(name="addressesses", default_value=bytes(packet_base / Dot15d4Data(dest_panid=0x1000) / packet_end), fuzz_values=[bytes(packet_base / Dot15d4Data(dest_panid=0x9234) / packet_end),
                                                                           bytes(packet_base / Dot15d4Data(dest_panid=0x1234) / packet_end),
                                                                           bytes(packet_base / Dot15d4Data(dest_panid=0x0033) / packet_end)]),
        )
    )
    for i in fuzzTest.get_mutations():
        print(i)
    
    session = Session(
        target=Target(
            connection=UDPSocketConnection("127.0.0.1", 52001)
        )
    )
    
    session.connect(fuzzTest)
    session.fuzz()
    
    '''                              
    conf.dot15d4_protocol = "zigbee"
    # send a ping and start the while loop
    print(packet_base / Dot15d4Data(dest_panid=0x1000, dest_addr=0x1234) / packet_end) 
    packet_bytes = bytes(packet_base / Dot15d4Data(dest_panid=0x1000) / packet_end)
    # udp.dstport == 52001
    gnuradio.sendto(packet_bytes, ("127.0.0.1", 52001))
    while True:
        data = gnuradio.recv(1024)
        time.sleep(1)
        print(Dot15d4FCS(data).show())
        gnuradio.sendto(packet_bytes, ("127.0.0.1", 52001))