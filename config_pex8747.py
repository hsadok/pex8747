#!/usr/bin/env python3

import asyncio
import errno
import logging
import os
import signal
import sys

from typing import Any

from ixypy import PCIDevice, PCIAddress
from ixypy.pci import PCIDeviceController, PCIException
from ixypy.register import MmapRegister

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

valid_device_ids = {
    0x8747: 'PEX8747',
}


# Function adapted from:
# https://github.com/barneygale/elevate/blob/master/elevate/posix.py
def elevate():
    if os.getuid() == 0:
        return

    command = ['sudo'] + [sys.executable] + sys.argv
    try:
        os.execlp(command[0], *command)
    except OSError as e:
        if e.errno != errno.ENOENT or command[0] == 'sudo':
            raise


class Pex8747Bridge(PCIDevice):
    def __init__(
        self,
        address: PCIAddress,
        pci_controller: PCIDeviceController | None = None,
    ):
        super().__init__(address, pci_controller)
        log.info('Vendor = %s', self.vendor())
        device_id = self.config().device_id
        if device_id in valid_device_ids:
            log.info(
                'Valid device detected: %s',
                valid_device_ids[device_id],
            )
        else:
            log.warning('Unknown device detected: 0x%x', device_id)

        if self.has_driver():
            log.info('Unbinding driver for device %s', self.address)
            self.unbind_driver()

        log.info('Device path: %s', self.path())

        try:
            mm = self.map_resource(resource_index=0)
        except PCIException:
            self.bar0 = None
        else:
            self.bar0 = MmapRegister(mm)

        if self.bar0:
            log.info('Mapped BAR0 for device %s', self.address)
            log.info('BAR0 size: %d bytes', mm.size())
            line = ''
            for i in range(0, 0x1000, 4):
                byte = self.bar0.get(i)
                if i % 16 == 0:
                    line = f'BAR0[{i:04x}]: '
                line += f'{byte:08x} '
                if (i + 4) % 16 == 0:
                    log.info('%s', line)
                    line = ''
            log.info('%s', line)


class Pex8747Switch:
    def __init__(self, up_port: str, down_port_1: str, down_port_2: str):
        self.up_port = Pex8747Bridge(PCIAddress.from_address_string(up_port))
        self.down_ports = [
            Pex8747Bridge(PCIAddress.from_address_string(down_port_1)),
            Pex8747Bridge(PCIAddress.from_address_string(down_port_2)),
        ]
        self.running = False
        log.info(
            'Pex8747Switch initialized with ports: %s, %s, %s',
            self.up_port.address,
            self.down_ports[0].address,
            self.down_ports[1].address,
        )

    def get_port_registers(self, port: int) -> list[Any]:
        assert self.up_port.bar0 is not None

        start_addr = 0x1000 * port
        end_addr = start_addr + 0x1000
        content = []
        for i in range(start_addr, end_addr, 4):
            word = self.up_port.bar0.get(i)
            content.append(word)
        return content

    def log_port_registers(
        self, port: int, skip_if_empty: bool = True
    ) -> bool:
        assert self.up_port.bar0 is not None

        content = self.get_port_registers(port)
        empty = all(word == 0 for word in content)

        if empty and skip_if_empty:
            return False

        line = ''
        for i, word in enumerate(content):
            if i % 4 == 0:
                line = f'Port {port:2}[{i * 4:04x}]: '
            line += f'{word:08x} '
            if (i + 1) % 4 == 0:
                log.info('%s', line)
                line = ''
        return True

    def log_all_ports(self):
        for i in range(18):
            if not self.log_port_registers(i):
                log.info('Port %2d:       [Empty]', i)

    async def monitor_changes(
        self, ports: list[int], interval: float = 1.0
    ) -> None:
        self.running = True
        port_states = {port: self.get_port_registers(port) for port in ports}

        while self.running:
            for port in ports:
                new_state = self.get_port_registers(port)
                old_state = port_states[port]
                for i, (old, new) in enumerate(zip(old_state, new_state)):
                    if old == new:
                        continue
                    log.info(
                        f'Change detected on Port {port} [{i * 4:04x}]: '
                        f'{old:08x} -> {new:08x}'
                    )
                port_states[port] = new_state
            log.info('')
            await asyncio.sleep(interval)

    def stop_monitoring(self) -> None:
        self.running = False


async def main():
    if len(sys.argv) != 4:
        print(f'Usage: python {sys.argv[0]} UP_PORT DOWN_PORT_1 DOWN_PORT_2')
        print(f'Example: python {sys.argv[0]} d8:00.0 d9:08.0 d9:10.0')
        sys.exit(1)

    elevate()

    up_port_bridge = sys.argv[1]
    down_port_bridge_1 = sys.argv[2]
    down_port_bridge_2 = sys.argv[3]

    switch = Pex8747Switch(
        up_port_bridge, down_port_bridge_1, down_port_bridge_2
    )
    switch.log_all_ports()

    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGINT, switch.stop_monitoring)

    monitor_task = asyncio.create_task(
        switch.monitor_changes([0, 8, 16], interval=1.0)
    )

    await monitor_task


if __name__ == '__main__':
    asyncio.run(main())
