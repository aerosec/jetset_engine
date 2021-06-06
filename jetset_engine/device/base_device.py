import device.synth

class SimGPIO(object):
    """docstring for GPIO"""
    def __init__(self, name, index, width=1, is_irq=False):
        self.name = name
        self.width = width
        self.is_irq = is_irq
        self.index = index
        

# Subdevice
class Simmio(object):
    def __init__(self, name, lower, upper, gpio_in = [], gpio_out = [], is_ic = False):
        self.name = name
        self.lower = lower
        self.upper = upper
        self.gpio_in = gpio_in
        self.gpio_out = gpio_out
        self.is_ic = is_ic
       
    def __repr__(self):
        return f"{self.name} mem[{hex(self.lower)}:{hex(self.upper)} gpio_in = {self.gpio_in}]"

# Class that holds all the memory / device config info
class BaseDevice(object):
    """docstring for DeviceBase"""
    def __init__(self):
        self.regions = []

    def mk_device(self):
        #self.io_protocol_summary()
        return device.synth.mk_device(self, rpi=self.rpi)

    def io_protocol_summary(self):
        return device.synth.io_protocol_summary(self)
        
    def load_config(self, regions):
        self.regions = regions
        