from device.base_device import Simmio
import angr
import cle

'''

0xA000 0000 - 0xA000 0FFF = FSMC control register
0x4000 0000 - 0x4007 FFFF = mmio
0x5000 0000 - 0x5006 0BFF = mmio 

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

dma_region = Simmio( lower=0x20000018,
                     upper= 0x2000001c,
                     name='dma_region')

regions = [block1, block2, fsmc_control_register, dma_region]


def get_project():        
    p = angr.Project("../jetset_public_data/p2im_firmware/Robot", auto_load_libs=False)
    return p

target = 0x08005275
arch = "arm"
arch_num = 1
