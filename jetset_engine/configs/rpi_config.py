from device.base_device import Simmio, SimGPIO
import angr
import cle

target = 0x000109d8 
arch = "arm"
arch_num = 1

'''
00000000-3bffffff : System RAM
00080000-00b3ffff : Kernel code
00fa0000-011a6fff : Kernel data
'''
dma = Simmio( lower=0x3f007000,
              upper=0x3f007fff,
              name='dma')

ic = Simmio(lower=0x3f00b200,
                 upper=0x3f00b3ff,
                 name='ic',
                 gpio_in=[SimGPIO(name="arm-irq", index=0, width=8)],
                 gpio_out=[SimGPIO(name="placeholder", index=1, is_irq=True)],
                 is_ic = True)

mailbox = Simmio(lower=0x3f00b800,
                     upper=0x3f00bbff,
                     name='mbox')

rng = Simmio(lower=0x3f104000,
                    upper=0x3f10400f,
                    name='rng')

gpio = Simmio(lower=0x3f200000,
                  upper=0x3f200fff,
                  name='gpio')

pl011 = Simmio(lower=0x3f201000,
                    upper=0x3f201fff,
                    name='pl011')

mmc = Simmio(lower=0x3f202000,
                 upper=0x3f202fff,
                 name='mmc')

i2c = Simmio(lower=0x3f205000,
                 upper=0x3f2050ff,
                 name='i2c')

aux = Simmio(lower=0x3f215000,
                 upper=0x3f215007,
                 name='aux')

sdhci = Simmio(lower=0x3f300000,
                   upper=0x3f3000ff,
                   name='sdhci')

dma_chan15 = Simmio(lower=0x3fe05000,
                   upper=0x3fe050ff,
                   name='dma_chan15')


soc_control = Simmio(lower=0x40000000,
                     upper=0x400000ff,
                     name='soc_control',
                     gpio_in=[SimGPIO(name="gpu-irq", index=0), SimGPIO(name="cntvirq",index=1)],
                     gpio_out=[SimGPIO(name="irq",index=2)],
                     is_ic = True)

regions = [dma,ic,mailbox,rng,gpio,pl011,mmc,i2c,aux,sdhci,dma_chan15, soc_control]

def get_project():
    bootloader_path = "../jetset_public_data/rpi/final/zImage"

    boot_load_opts = {'backend' : 'blob',
                      'base_addr' : 0x10000,
                      'entry_point' : 0x10000,
                      'arch' : 'ARMEL'}

    p = angr.Project(bootloader_path,
                     load_options={'main_opts': boot_load_opts},
                     rebase_granularity=0x1000,
                     auto_load_libs=False)

    dtb = cle.backends.Blob('../jetset_public_data/rpi/final/bcm2709-rpi-2-b.dtb',
                          arch='ARMEL',
                          base_addr=0x8000000)
    p.loader.add_object(dtb)

    vmlinux = cle.backends.ELF('../jetset_public_data/rpi/final/vmlinux', arch='ARMEL', loader=p.loader)
    p.loader.add_object(vmlinux)

    return p

