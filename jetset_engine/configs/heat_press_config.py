from device.base_device import Simmio
import angr
import cle

peripherals = Simmio( lower=0x40000000,
                 upper=0x5FFFFFFF,
                 name='peripherals')

regions = [peripherals]

def get_project():        
    p = angr.Project("../jetset_public_data/p2im_firmware/Heat_Press", auto_load_libs=False)
    return p

target = 0x816c1
arch = "arm"
arch_num = 1
