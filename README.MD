# Zigbee Learning
This repo contains the experiments for my thesis project. The goal is to employ machine learning to create a model of a Zigbee device. 

My thesis can be downloaded here at the [OU Research portal](https://research.ou.nl/en/studentTheses/automata-learning-for-behavioural-mapping-of-zigbee-devices/)

A public version of this repo is available online at [https://github.com/olijf/zigbee-learning/](https://github.com/olijf/zigbee-learning/)

This work relies heavely on Scapy and other tooling.

Inspired by [Andrea Pferscher's work on BLE Model learning](https://github.com/apferscher/ble-learning)

We have explored two options in our experiments:
1. **Zigbee2MQTT**: A popular open-source Zigbee to MQTT bridge that allows you to control Zigbee devices from your home automation system.
2. **WPAN (IEEE 802.15.4)**: A low-rate wireless personal area network (LR-WPAN) that can be hacked to speak Zigbee. 

## Requirements
A Linux machine, several Zigbee dongles and a Zigbee device.

## Zigbee2MQTT
We used a CC2531 USB dongle with the firmware flashed with Zigbee2MQTT. The firmware can be found at [Koenkk/Z-Stack-firmware](https://github.com/Koenkk/Z-Stack-firmware)

## WPAN (IEEE 802.15.4)
We used a WPAN enabled TI CC2531 dongle. A firmware and kernel module can be found at [rosvall/cc2531_linux](https://github.com/rosvall/cc2531_linux) to be flashed on the dongle.
WPAN provides a network interface but we can not rely on the the linux kernel being able to handle Zigbee frames. Check the [frameprovider](./zigbee_frames/frameprovider.py) to see how we can craft those frames in Scapy.

## How to run
A docker container is provided under [dataset-generation](./dataset-generation/README.md) to run the experiments. Then we can start the learning process using the [mqttlearning.py](./mqttlearning.py) script.

The second experiment makes use of the network already created using Zigbee2MQTT, first we stop the docker container and then we can run the [wpanlearning.py](./wpanlearning.py) script.
This takes over the already established network and starts sending probes to make the device think the network is still up. We have to power cycle the device to reset its counters and then the learning process will start.

## Results
There are several PDF's in this repo with the results of the experiments. 
