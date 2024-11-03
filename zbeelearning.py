from whad.device import WhadDevice
from whad.zigbee import Coordinator
from whad.common.monitors import WiresharkMonitor
from whad.zigbee.stack.apl.application import ApplicationObject
from whad.zigbee.stack.apl.zcl.clusters.onoff import OnOffServer, ZCLCluster
from whad.zigbee.stack.apl.zcl.clusters.touchlink import ZCLTouchLinkClient
from whad.exceptions import WhadDeviceNotFound
from scapy.compat import raw
from random import randint
import sys
import logging
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()],
)

# Now, all logging calls in the application will output to the command line

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface

        interface = sys.argv[1]

        try:
            monitor = WiresharkMonitor()

            dev = WhadDevice.create(interface)

            # Define a custom ON/OFF ZCL Server
            class CustomOnOffServer(OnOffServer):

                @ZCLCluster.command_receive(0x00, "Off")
                def on_off(self, command):
                    super().on_off(command)
                    print("-> Custom Off")

                @ZCLCluster.command_receive(0x01, "On")
                def on_on(self, command):
                    super().on_on(command)
                    print("-> Custom On")

                @ZCLCluster.command_receive(0x02, "Toggle")
                def on_toggle(self, command):
                    super().on_toggle(command)
                    print("-> Custom Toggle")

            # Instantiate the custom OnOff ZCL Server
            onoff = CustomOnOffServer()
            touchlink = ZCLTouchLinkClient()

            # Create an Application object and set OnOff ZCL as input cluster
            touchlinking = ApplicationObject(
                "ZLL",
                profile_id = 0xc05e,
                #profile_id=0x0104,
                device_id = 0x0840,
                device_version = 0,
                output_clusters=[
                    touchlink
                ]
            )
            
            basicapp = ApplicationObject(
                "Basic",
                profile_id = 0x0104,
                device_id = 0x0100,
                device_version = 0,
                output_clusters=[
                    onoff
                ]
            )
            #touchlinking
            # Instantiate a coordinator with our application object
            coordinator = Coordinator(dev, applications=[basicapp])

            # Attach & start the wireshark monitor
            monitor.attach(coordinator)
            monitor.start()

            # Start the coordinator
            coordinator.start()

            # Start a network formation
            print("[i] Network formation !")
            network = coordinator.start_network()
            print(network)
            while True:
                # When there is an user input, discover the network
                input()
                #touchlink.scan()
                for device in network.discover():
                    print("[i] New device discovered:", device)

                # Iterate over the devices in the network
                for device in network.nodes:
                    # For each device, iterate over the endpoints
                    for endpoint in device.endpoints:
                        # If a OnOff is found in endpoint, attach to the cluster
                        if endpoint.profile_id == 0x0104 and 6 in endpoint.input_clusters:
                            onoff = endpoint.attach_to_input_cluster(6)
                            while True:
                                input()
                                # Manipulate the OnOff cluster API to toggle the state
                                print("[i] lightbulb toggled")
                                onoff.toggle()

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])