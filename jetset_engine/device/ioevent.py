class IOPortRead(object):
	"""docstring for IOPortRead"""
	def __init__(self, portno, symbol):
		super(IOPortRead, self).__init__()
		self.portno = portno
		self.symbol = symbol
		self.is_mmio = False
		self.is_ioport = True
		self.is_read = True
		self.is_ic = False
		self.is_gpio = False
		self.is_ioport = True

	def __repr__(self):
		return f"IOPort Read @ {hex(self.portno)}"
	
class IOPortWrite(object):
	"""docstring for IOPortWRite"""
	def __init__(self, portno, val):
		super(IOPortWrite, self).__init__()
		self.portno = portno
		self.val = val
		self.is_mmio = False
		self.is_ioport = True
		self.is_read = False
		self.is_ic = False
		self.is_gpio = False
		self.is_ioport = True

	def __repr__(self):
		return f"IOPort Write @ {hex(self.portno)} = {hex(self.val)}"

class MMIORead(object):
	"""docstring for MMIORead"""
	def __init__(self, addr, symbol):
		super(MMIORead, self).__init__()
		self.addr = addr
		self.symbol = symbol
		self.is_mmio = True
		self.is_ioport = False
		self.is_read = True
		self.is_ic = False
		self.is_gpio = False
		self.is_ioport = False

	def __repr__(self):
		return f"MMIO Read @ {hex(self.addr)}"

class MMIOWrite(object):
	"""docstring for MMIOWrite"""
	def __init__(self, addr, val):
		super(MMIOWrite, self).__init__()
		self.addr = addr
		self.val = val
		self.is_mmio = True
		self.is_ioport = False
		self.is_read = False
		self.is_ic = False
		self.is_gpio = False
		self.is_ioport = False

	def __repr__(self):
		return f"MMIOWrite @ {hex(self.addr)} = {hex(self.val)}"

class IntcRead(object):
	"""docstring for MMIORead"""
	def __init__(self, addr, val):
		super(IntcRead, self).__init__()
		self.addr = addr
		self.val = val
		self.is_mmio = False
		self.is_ioport = False
		self.is_read = True
		self.is_ic = True
		self.is_gpio = False
		self.is_ioport = False

	def __repr__(self):
		return f"Intc Read @ {hex(self.addr)} = {hex(self.val)}"


class GPIOSet(object):
	"""docstring for MMIORead"""
	def __init__(self, irq, val):
		super(GPIOSet, self).__init__()
		self.irq = irq
		self.val = val
		self.is_read = False
		self.is_mmio = False
		self.is_ioport = False
		self.is_ic = False
		self.is_gpio = True
		self.is_ioport = False
	
	def __repr__(self):
		return f"GPIO set @ irq#{self.irq} = {self.val}"

		
