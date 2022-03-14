# Jetset Symbolic Execution Coordinator

This repository coordinates Jetset's symbolic execution by spinning up a server that communicates with `jetset_qemu` via qemu monitor commands (`qmp.py`).

## Configuring Additional Devices

`jetset_engine/configs` defines configuration files for additional devices. 
You should add your device model to this directory (look at `drone_config.py` for an example). 
This device model must include an `arch_num` field that specifies the architecture of the device: these are defined in `jetset_qemu/include/exec/synth_controller.h`:

```
#define ARCHNAME_ARM  1
#define ARCHNAME_M68K 2
#define ARCHNAME_X86  3
...
```

For example, your file may look something like this:

```
from device.base_device import Simmio
import angr
import cle

target = 0x21e86ba9
# potentially add avoid = [{list of avoid addrs}]
arch = "x86"
arch_num = 3

simple_synth_0 = Simmio(lower=0x21E80000,
                   upper=0x21E8B000,
                   name='simple_synth_0')

regions=[simple_synth_0]

def get_project():        
    firmware_path = "../firmware/myDevice-ram.bin"
    boot_load_opts = {'backend' : 'blob',
                      'base_addr' : 0x21E80000,
                      'entry_point' : 0xFFFFFFF0,
                      'arch' : 'x86'}
    p = angr.Project(firmware_path,
                     load_options={'main_opts': boot_load_opts},
                     rebase_granularity=0x1000,
                     auto_load_libs=False)
    return p
```

After adding one of these, you will need to add a dictionary field pointing to the class in `./configs/socs.py`.
After this is done, the config will properly resolve the `--soc` flag when running jetset, and you can add a rule to the jetset root Makefile, e.g.

```
run_myDevice:
  source jetset_env/bin/activate && cd $(ENGINE_BASE) && python $(ENGINE_SCRIPT) --soc=myDevice --useFinalizer --useSlicer --cmdfile ../jetset_qemu/run_myDevice_qemu.sh
```

Note the `../jetset_qemu/run_myDevice_qemu.sh` file. 
Explanation of how to create this is in the readme of the jetset\_qemu repository.

## Debugging

Some tips:
- You may want to see what events are being communicated between the engine and qemu; for this, print out the msg variable in `jetset_engine/qmp_channel.py`
