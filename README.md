# PEX 8747

Script to retrieve statistics from the PEX 8747 PCIe switch.

## Setup
Initialize submodules:
```bash
git submodule update  --init
```

Install the dependencies:
```bash
python3 -m venv venv
source venv/bin/activate
pip3 install -e ./ixy
```
## Run
To identify all the PCIe bridges from PEX, run:
```bash
sudo lspci -d10b5:
```

Activate the virtual environment if not already activated.
```bash
source venv/bin/activate
```

Now run the script specifying the PCIe address of the upstream PEX 8747 bridge for the switch:
```bash
./pex8747.py SWITCH_UP_BRIDGE
```

### Example

Run `lspci` to find the upstream bridge address:

```bash
sudo lspci -d10b5:

d8:00.0 PCI bridge: PLX Technology, Inc. PEX 8747 48-Lane, 5-Port PCI Express Gen 3 (8.0 GT/s) Switch (rev ca)
d9:08.0 PCI bridge: PLX Technology, Inc. PEX 8747 48-Lane, 5-Port PCI Express Gen 3 (8.0 GT/s) Switch (rev ca)
d9:10.0 PCI bridge: PLX Technology, Inc. PEX 8747 48-Lane, 5-Port PCI Express Gen 3 (8.0 GT/s) Switch (rev ca)
```

In this example the upstream bridge is `d8:00.0`. Then run:

```bash
./pex8747.py d8:00.0
```
