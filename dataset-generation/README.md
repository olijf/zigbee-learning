# Dataset-generation
Instead of having to drag around a Philips Hue bridge, we can use the Zigbee to MQTT project to setup a basic coordinator.

## Prerequisites
- Docker
- A CC2531 dongle flashed with the koenkk firmware

## Setup
1. check in the `docker-compose.yml` and the zigbee2mqtt `configuration.yml` files if everything seems suitable for your setup, serial ports are in the right location etc.
2. `docker compose up -d`
3. navigate to `http://localhost:8080` to see the zigbee2mqtt interfaces

## Sniffing key
the key is set in in the `configuration.yml` file, it is used to decrypt the traffic.
To see traffic decoded in wireshark add it under `Edit -> Preferences -> Protocols -> Zigbee -> Keys`

Once you have put in the Trust Center key (google it) you can figure out the network key by sniffing a join procedure.
Add the network key to decrypt the rest of the traffic, you only have to do this once.


