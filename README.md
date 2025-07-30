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
pip3 install -e ixy.py
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

Now run the script specifying the PCIe address of all the PEX 8747 bridge associated with the same switch:
```bash
./config_pex8747.py UP_PORT DOWN_PORT1 DOWN_PORT2
```

For example:
```bash
./config_pex8747.py d8:00.0 d9:08.0 d9:10.0
```
