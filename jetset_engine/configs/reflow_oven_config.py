from device.base_device import Simmio
import angr
import cle

'''

0xA000 0000 - 0xA000 0FFF = FSMC control register
0x4000 0000 - 0x4007 FFFF = bunch of mmio
0x5000 0000 - 0x5006 0BFF = more mmio junk

'''

block1 = Simmio( lower=0x40000000,
                 upper=0x4007FFFF,
                 name='block1')


block2 = Simmio( lower=0x50000000,
                 upper= 0x50060BFF,
                 name='block2')

fsmc_control_register = Simmio( lower=0xA0000000,
                                upper= 0xA0000FFF,
                                name='fsmc_control_register')

regions = [block1, block2, fsmc_control_register]


def get_project():        
    p = angr.Project("../jetset_public_data/p2im_firmware/Reflow_Oven", auto_load_libs=False)
    return p

target = 0x08005f7b
arch = "arm"
arch_num = 1
