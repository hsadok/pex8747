#!/usr/bin/env python3

import asyncio
import errno
import logging
import os
import signal
import sys

from collections import defaultdict
from typing import Any

from ixypy import PCIDevice, PCIAddress
from ixypy.pci import PCIDeviceController, PCIException
from ixypy.register import MmapRegister

logging.basicConfig(level=logging.WARN)
log = logging.getLogger(__name__)

CONTROL_OFFSET = 0x3E0
FIFO_OFFSET = 0x3E4
RAM_CTRL_OFFSET = 0x3F0

NB_STATIONS = 3
COUNTERS_PER_PORT = 14
PORTS_PER_STATION = 6
COUNTERS_PER_STATION = PORTS_PER_STATION * COUNTERS_PER_PORT

valid_device_ids = {
    0x8747: 'PEX8747',
}

stats_names = {
    'in_ph': 'Ingress Posted Headers',
    'in_pdw': 'Ingress Posted DWords',
    'in_npdw': 'Ingress Non-Posted DWords',
    'in_cplh': 'Ingress Completion Headers',
    'in_cpldw': 'Ingress Completion DWords',
    'eg_ph': 'Egress Posted Headers',
    'eg_pdw': 'Egress Posted DWords',
    'eg_npdw': 'Egress Non-Posted DWords',
    'eg_cplh': 'Egress Completion Headers',
    'eg_cpldw': 'Egress Completion DWords',
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


class Pex8747Switch:
    def __init__(self, up_port: str):
        self.up_port = Pex8747Bridge(PCIAddress.from_address_string(up_port))
        self.running = False
        log.info(
            'Pex8747Switch initialized with port: %s', self.up_port.address
        )

    def get_reg(self, offset: int) -> int:
        assert self.up_port.bar0 is not None
        return int(self.up_port.bar0.get(offset))

    def set_reg(self, offset: int, value: int) -> None:
        assert self.up_port.bar0 is not None
        self.up_port.bar0.set(offset, value)

    def enable_monitoring(self) -> None:
        assert self.up_port.bar0 is not None

        # Disable probe mode interval timer.
        reg_value = self.get_reg(0x3F0)
        reg_value |= 3 << 8
        self.set_reg(0x3F0, reg_value)

        for i in range(NB_STATIONS):
            offset = i * 0x1000 * 8
            reg_value = self.get_reg(offset + 0x768)
            reg_value |= 0b1 << 29
            self.set_reg(offset + 0x768, reg_value)

            reg_value = self.get_reg(offset + 0xF30)
            reg_value |= 0b1 << 6  # Enable egress counters.
            self.set_reg(offset + 0xF30, reg_value)

        # Reset and enable monitoring.
        reg_value = 0
        reg_value |= 0b1 << 31
        reg_value |= 0b1 << 30
        reg_value |= 0b1 << 28
        reg_value |= 0b1 << 27
        self.set_reg(CONTROL_OFFSET, reg_value)

    def disable_monitoring(self) -> None:
        assert self.up_port.bar0 is not None

        for i in range(NB_STATIONS):
            offset = i * 0x1000 * 8
            reg_value = self.get_reg(offset + 0x768)
            reg_value &= ~(0b1 << 29) & 0xFFFFFFFF
            self.set_reg(offset + 0x768, reg_value)

            reg_value = self.get_reg(offset + 0xF30)
            reg_value &= ~(0b1 << 6) & 0xFFFFFFFF  # Disable egress counters.
            self.set_reg(offset + 0xF30, reg_value)

        # Reset and disable monitoring.
        reg_value = 0
        reg_value |= 0b1 << 30
        self.set_reg(CONTROL_OFFSET, reg_value)

    def reset_stats(self) -> None:
        assert self.up_port.bar0 is not None

        reg_value = 0
        reg_value |= 0b1 << 31
        reg_value |= 0b1 << 30
        reg_value |= 0b1 << 28
        reg_value |= 0b1 << 27

        self.set_reg(CONTROL_OFFSET, reg_value)

    def get_port_stats(self, ports: list[int]) -> dict[int, dict[str, int]]:
        assert self.up_port.bar0 is not None

        # RAM control.
        reg_value = 0
        reg_value |= 0b10 << 4  # Capture type.
        reg_value |= 0b01 << 2  # Reset read pointer.
        reg_value |= 0b01 << 0  # Enable RAM.

        self.set_reg(RAM_CTRL_OFFSET, reg_value)

        raw_counters = []
        for _ in range(0, NB_STATIONS * COUNTERS_PER_STATION):
            word = self.get_reg(FIFO_OFFSET)
            raw_counters.append(word)

        log.info('Raw counters:')
        line = ''
        for i, word in enumerate(raw_counters):
            if i % 4 == 0:
                line = f'[{i * 4:04x}]: '
            line += f'{word:08x} '
            if i % COUNTERS_PER_STATION == COUNTERS_PER_STATION - 1:
                line += '\n'
            if (i + 1) % 4 == 0:
                log.info('%s', line)
                line = ''

        stats = {}
        for port in ports:
            port_stats = {}

            station_offset = (port // PORTS_PER_STATION) * COUNTERS_PER_STATION

            offset = station_offset + 5 * (port % PORTS_PER_STATION)
            log.info('Port %d ingress offset: 0x%x', port, offset * 4)
            port_stats['in_ph'] = raw_counters[offset + 0]
            port_stats['in_pdw'] = raw_counters[offset + 1]
            port_stats['in_npdw'] = raw_counters[offset + 2]
            port_stats['in_cplh'] = raw_counters[offset + 3]
            port_stats['in_cpldw'] = raw_counters[offset + 4]

            offset += 5 * PORTS_PER_STATION
            log.info('Port %d egress offset: 0x%x', port, offset * 4)
            port_stats['eg_ph'] = raw_counters[offset + 0]
            port_stats['eg_pdw'] = raw_counters[offset + 1]
            port_stats['eg_npdw'] = raw_counters[offset + 2]
            port_stats['eg_cplh'] = raw_counters[offset + 3]
            port_stats['eg_cpldw'] = raw_counters[offset + 4]

            stats[port] = port_stats

        return stats

    def print_stats(self, ports: list[int] | None = None) -> None:
        ports = ports or list(range(PORTS_PER_STATION * NB_STATIONS))
        stats = self.get_port_stats(ports)

        for port, counters in stats.items():
            print(f'Port {port} stats:')
            for name, value in counters.items():
                print(f'  {stats_names.get(name, name)}: {value}')

    def get_port_registers(self, port: int) -> list[Any]:
        assert self.up_port.bar0 is not None

        start_addr = 0x1000 * port
        end_addr = start_addr + 0x1000
        content = []
        for i in range(start_addr, end_addr, 4):
            word = self.get_reg(i)
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

    async def monitor_stats(
        self, ports: list[int], interval: float = 1.0
    ) -> None:
        self.running = True
        self.enable_monitoring()
        self.reset_stats()

        # aggregated_stats = {port: defaultdict(int) for port in ports}
        adj = {port: defaultdict(int) for port in ports}
        all_port_stats = self.get_port_stats(ports)
        for name, value in all_port_stats[0].items():
            adj[0][name] = -value

        while self.running:
            old_stats = all_port_stats
            all_port_stats = self.get_port_stats(ports)

            # Correct wrap-around.
            for port, port_stats in all_port_stats.items():
                for name in port_stats.keys():
                    value = port_stats[name]
                    old_value = old_stats[port].get(name, 0)
                    if value < old_value:
                        adj[port][name] += 2**32

            # Discount overhead of retrieving stats.
            nb_wr_req = 1
            nb_rd_req = NB_STATIONS * COUNTERS_PER_STATION

            adj[0]['in_ph'] -= nb_wr_req

            # DLLP (2 DWORDS) + MWr32 header (3 DWORDS) + 1 DWORD payload
            adj[0]['in_pdw'] -= (3 + 2 + 1) * nb_wr_req

            # DLLP (2 DWORDS) + MRd32 header (3 DWORDS)
            adj[0]['in_npdw'] -= (3 + 2) * nb_rd_req

            adj[0]['eg_cplh'] -= nb_rd_req

            # DLLP (2 DWORDS) + Cpl header (3 DWORDS) + 1 DWORD payload
            adj[0]['eg_cpldw'] -= (3 + 2 + 1) * nb_rd_req

            for port, port_stats in all_port_stats.items():
                s = port_stats.copy()
                for name in s.keys():
                    s[name] += adj[port][name]

                # Assuming non-posted TLPs are MRd64.
                in_nph = s['in_npdw'] // (4 + 2)
                eg_nph = s['eg_npdw'] // (4 + 2)

                in_tlps = s['in_ph'] + s['in_cplh'] + in_nph
                eg_tlps = s['eg_ph'] + s['eg_cplh'] + eg_nph

                in_bytes = (
                    s['in_pdw'] * 4 + s['in_cpldw'] * 4 + s['in_npdw'] * 4
                )
                eg_bytes = (
                    s['eg_pdw'] * 4 + s['eg_cpldw'] * 4 + s['eg_npdw'] * 4
                )

                print(f'Port {port} stats:')
                print('  Ingress:')
                print(
                    f'     TLPs: {in_tlps}  (Posted: {s["in_ph"]}, '
                    f'Non-Posted: {in_nph}, Completion: {s["in_cplh"]})'
                )
                print(
                    f'    Bytes: {in_bytes}  (Posted: {s["in_pdw"] * 4}, '
                    f'Non-Posted: {s["in_npdw"] * 4}, '
                    f'Completion: {s["in_cpldw"] * 4})'
                )
                print('   Egress:')
                print(
                    f'     TLPs: {eg_tlps}  (Posted: {s["eg_ph"]}, '
                    f'Non-Posted: {eg_nph}, Completion: {s["eg_cplh"]})'
                )
                print(
                    f'    Bytes: {eg_bytes}  (Posted: {s["eg_pdw"] * 4}, '
                    f'Non-Posted: {s["eg_npdw"] * 4}, '
                    f'Completion: {s["eg_cpldw"] * 4})'
                )
            print('')
            await asyncio.sleep(interval)

        self.disable_monitoring()

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

    def stop_running(self) -> None:
        self.running = False


async def main():
    if len(sys.argv) != 2:
        print(f'Usage: python {sys.argv[0]} SWITCH_UP_BRIDGE')
        print(f'Example: python {sys.argv[0]} d8:00.0')
        sys.exit(1)

    elevate()

    up_port_bridge = sys.argv[1]

    switch = Pex8747Switch(up_port_bridge)

    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGINT, switch.stop_running)

    monitor_task = asyncio.create_task(
        switch.monitor_stats([0, 6, 12], interval=1.0)
    )

    await monitor_task


if __name__ == '__main__':
    asyncio.run(main())
