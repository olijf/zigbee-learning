from zigbee_frames.transceive import Transceiver
from util.wpan_interface import Phy
from scapy.all import conf, CacheInstance

if __name__ == '__main__':
    #from util.wpan_interface import Phy
    
    source_addr = bytes.fromhex("00:12:4b:00:1c:dd:27:3d".replace(":", ""))
    phy=Phy(int.from_bytes(source_addr), initial_channel=11, initialize=True, debug_monitor=False)
    Transceiver.receive(iface="wpan0", chan=11, phy=phy)