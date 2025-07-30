#!/usr/bin/env python3

import sys
import logging

from ixypy import PCIDevice, PCIAddress

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

valid_device_ids = {
    0x8747: 'PEX8747',
}

def init_device(pci_address: str) -> None:
    address = PCIAddress.from_address_string(pci_address)
    device = PCIDevice(address)
    log.info("Vendor = %s", device.vendor())
    if device.config().device_id in valid_device_ids:
        log.info("Valid device detected: %s", valid_device_ids[device.config().device_id])
    else:
        log.warning("Unknown device detected: 0x%x", device.config().device_id)


def main():
    if len(sys.argv) != 4:
        print(f"Usage: python {sys.argv[0]} UP_PORT_BRIDGE DOWN_PORT_BRIDGE_1 DOWN_PORT_BRIDGE_2")
        print(f"Example: python {sys.argv[0]} d8:00.0 d9:08.0 d9:10.0")
        sys.exit(1)
    up_port_bridge = sys.argv[1]
    down_port_bridge_1 = sys.argv[2]
    down_port_bridge_2 = sys.argv[3]
    up_port = init_device(up_port_bridge)
    down_port_1 = init_device(down_port_bridge_1)
    down_port_2 = init_device(down_port_bridge_2)

if __name__ == "__main__":
    main()
