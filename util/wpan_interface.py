import os
import logging

class Phy:
    def __init__(self, source_address: int, initial_channel: int, initialize: bool = True, debug_monitor: bool = False, pan_id=0x1a62):
        '''
        
        
        '''
        
        self.source = source_address
        if initialize:
            self.phy = self._initialization(pan_id)
            self.switch_channel(initial_channel)
        else:
            self.phy = self._find_phy_device()
            if debug_monitor:
                self._enable_debug_monitor()
                
        
    def get_phy(self) -> str:
        return self.phy
    
    def switch_channel(self, chan):
        logging.info(f"Switching to channel {chan}")
        # iwpan phy <phyname> set channel <page> <channel>
        os.system(f"iwpan phy {self.phy} set channel 0 {chan}")

    def _initialization(self, pan_id) -> str:
        #first configure the wpan adapter
        #find the first phy by running iwpan phy
        #on the first line you will see the phy name, use that in the following commands
        phy = self._find_phy_device()
            
        logging.info(f"Using phy: {phy}")
        
        self._delete_interfaces()
        
        #add a new interface
        logging.debug(f"source addres = {self.source}")
        #convert the source address to hex seperated by :
        source_hex = self.source.to_bytes(8, 'big').hex(':')
        
        logging.info(f"source addres = {source_hex}")
        
        os.system(f"iwpan phy {phy} interface add wpan0 type node {source_hex}")
        os.system(f"ip link set wpan0 down")
        os.system(f"iwpan dev wpan0 set pan_id {pan_id}")
        short_addr = 0x0000
        os.system(f"iwpan dev wpan0 set short_addr {short_addr}")
        #set the channel to 11
        os.system(f"iwpan phy {phy} set channel 0 11")
        logging.info("Setting up the ip link")
        #bring the interface up
        os.system(f"ip link set wpan0 up")
        return phy

    def _get_interfaces(self):
        interfaces = os.popen("iwpan dev").read()
        interfaces = [line.split(" ")[1] for line in interfaces.split("\n") if line.strip().startswith('Interface ') ]
        return interfaces

    def _enable_debug_monitor(self):
        self._delete_interfaces()
        #can't have two interfaces on the same adapter, so disable the init
        #iwpan phy <phy> interface add mon0 type monitor
        #ip link set mon0 up
        os.system(f"iwpan phy {self.phy} interface add monitor%d type monitor")
        monitors = [iface for iface in self._get_interfaces() if iface.startswith("monitor") ]
        
        logging.debug(f"Monitors: {' '.join(monitors)}")
        logging.debug(f"Enabling monitor {monitors[0]}")
        os.system(f"ip link set {monitors[0]} up")
    
    def _find_phy_device(self):
        output = os.popen("iwpan phy").read()
        #output looks like this: wpan_phy phy3
        try:
            phy = output.split("\n")[0].split(" ")[1]
        except IndexError:
            logging.error("No phy found, are you sure you have plugged in the wpan stick?")
            exit(1)
        return phy
    
    def _delete_interfaces(self):
        #get the interfaces
        interfaces = self._get_interfaces()
        
        #delete any interfaces that are already there
        for interface in interfaces:
            logging.debug(f"Deleting {interface}")
            if os.system(f"iwpan dev {interface} del"):
                logging.debug(f"Deleted {interface}")
        

if __name__ == '__main__':
    source = int('00124b001cdd273d', 16)
    phy = Phy(source, 11, debug_monitor=False)
    