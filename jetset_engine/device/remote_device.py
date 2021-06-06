import claripy
from device.device_ops import *
from analysis.debug import *
from device.base_device import BaseDevice
from device.ioevent import *
from device.slicer import ConstraintSlicer
from device.symbol_link import SymbolLink

class SymbolicDevice(BaseDevice):
    """docstring for SymbolicDevice"""
    def __init__(self, use_slicer=False, rpi=False):
        super(SymbolicDevice, self).__init__()
        self.trace = []
        self.solver = claripy.Solver(track=True)
        self.symbol_map = {}
        self.idx_map = {}
        self.use_slicer = use_slicer
        self.slicer = ConstraintSlicer(self)
        self.link = SymbolLink()
        self.rpi = rpi

    def arg_to_symbol(self, symbol, is_symbolic):
        if is_symbolic:
            return self.symbol_map[symbol]
        else:
            return symbol

    def eval(self, symbol):
        # concretize a symbol
        return self.solver.eval(symbol,1)[0]

    def ioport_reads(self):
        for event in self.trace:
            if event.is_read and not event.is_mmio:
                yield event

    def mmio_reads(self):
        for event in self.trace:
            if event.is_mmio and event.is_read:
                yield event

    def subtrace(self, subdev):
        for event in self.trace:
            if event.is_mmio:
                if (event.addr >= subdev.lower) and (event.addr <= subdev.upper):
                    yield event
            if event.is_gpio:
                if event.irq in subdev.gpio_in:
                    yield event

    def add_symbol(self, symbol, size):
        symbolic_v = claripy.BVS(str(symbol), size)
        self.symbol_map[symbol] = symbolic_v
        self.idx_map[symbolic_v.args[0]] = symbol
        self.slicer.add_symbol(symbol)
        return symbolic_v

    def add_mmio_read(self, addr, symbol, size):
        symbolic_v = self.add_symbol(symbol,size*8)
        self.trace.append(MMIORead(addr, symbolic_v))

    def add_mmio_write(self, addr, val):
        self.trace.append(MMIOWrite(addr, val))

    def add_intc_read(self, addr, val):
        self.trace.append(IntcRead(addr, val))

    def add_ioport_read(self, portno, symbol):
        symbolic_v = self.add_symbol(symbol,32)
        self.trace.append(IOPortRead(portno, symbolic_v))

    def add_ioport_write(self, portno, val):
        self.trace.append(IOPortWrite(portno, val))

    def add_gpio_set(self, irq, val):
        self.trace.append(GPIOSet(irq, val))

    def add_constraint(self, c):
        self.solver.add(c)
        self.link.link_varn(*c.variables)

    def add_binop_constraint(self, dst, opc, v0, v1):
        constraint = binop_to_constraint(opc,v0,v1)
        dst_symbol = self.add_symbol(dst, len(constraint))
        self.add_constraint(dst_symbol == constraint)
        if self.use_slicer:
            self.slicer.add_binop_deps(dst, v0, v1)

    def add_unop_constraint(self, dst, opc, v):
        constraint = unop_to_constraint(opc,v)
        dst_symbol = self.add_symbol(dst, len(constraint))
        self.add_constraint(dst_symbol == constraint)
        if self.use_slicer:
            self.slicer.add_unop_deps(dst, v)

    def add_deposit_constraint(self, dst, v0, v1, c0, c1):
        constraint = deposit_to_constraint(v0,v1,c0,c1)
        dst_symbol = self.add_symbol(dst, len(constraint))
        self.add_constraint(dst_symbol == constraint)
        if self.use_slicer:
            self.slicer.add_binop_deps(dst, v0, v1)

    def add_setcond_constraint(self, dst, v0, v1, condition):
        constraint = setcond_to_constraint(condition, v0, v1)
        dst_symbol = self.add_symbol(dst, 32)
        self.add_constraint(dst_symbol == constraint)
        if self.use_slicer:
            self.slicer.add_binop_deps(dst, v0, v1)

    def add_x86_ccall_constraints(self, dst_is_symbolic,
                                  arg0_is_symbolic,
                                  arg1_is_symbolic,
                                  arg2_is_symbolic,
                                  arg3_is_symbolic,
                                  dst,
                                  arg0,arg1,arg2,arg3):

        arg0_symbol = self.arg_to_symbol(arg0, arg0_is_symbolic)
        constraint = x86_flags[arg3](arg0_symbol)
        dst_symbol = self.add_symbol(dst, len(constraint))

        self.add_constraint(dst_symbol == constraint)
        if self.use_slicer:
            self.slicer.add_unop_deps(dst, arg0_symbol)


    def sat_choices(self, arg1, arg2, condition):
        constraint = choice_to_constraint(condition,arg1,arg2)
        not_constraint = claripy.Not(constraint)

        if self.use_slicer:
            s = claripy.Solver()
            sliced_constraints = self.slicer.slice_constraint(self.solver.constraints, arg1, arg2)
            logger.trace_log(f"# of sliced constraints: {len(sliced_constraints)} {sliced_constraints}")
            s.add(sliced_constraints)
        else:
            s = claripy.Solver()
            s.add(self.solver.constraints)

        zero_sat = s.satisfiable(extra_constraints=[not_constraint])
        one_sat = s.satisfiable(extra_constraints=[constraint])
        return zero_sat,one_sat

    def add_decision_constraint(self, arg1, arg2, condition, decision):
        if decision:
            constraint = choice_to_constraint(condition,arg1,arg2)
        else:
            constraint = claripy.Not(choice_to_constraint(condition,arg1,arg2))
        self.add_constraint(constraint)

    def get_relevant_io(self, s):
        relevant_io = []
        relevant_vars = self.slicer.find(s)
        for mmio_read in self.mmio_reads():
            symbol_idx = self.slicer.get_symbol(mmio_read.symbol)
            if symbol_idx in relevant_vars:
                relevant_io.append(mmio_read)
        return relevant_io

    def finalize_mmio_read(self, condition, arg1, arg1_is_symbolic, arg2, arg2_is_symbolic, decision):
        arg1_symbol = self.arg_to_symbol(arg1, arg1_is_symbolic)
        arg2_symbol = self.arg_to_symbol(arg2, arg2_is_symbolic)
        constraint = choice_to_constraint(condition, arg1_symbol, arg2_symbol)
        if decision == 0:
            constraint = claripy.Not(constraint)
        relevant_reads = []
        if arg1_is_symbolic:
            relevant_reads.extend(self.get_relevant_io(arg1))
        if arg2_is_symbolic:
            relevant_reads.extend(self.get_relevant_io(arg2))
        assert(len(relevant_reads) == 1)
        addr_to_concretize = relevant_reads[0].addr
        symbol_to_concretize = relevant_reads[0].symbol
        s = claripy.Solver()
        sliced_constraints = self.slicer.slice_constraint(self.solver.constraints, arg1, arg2)
        s.add(sliced_constraints)
        concretized_val = s.eval(symbol_to_concretize,1,extra_constraints=[constraint])[0]
        return addr_to_concretize,concretized_val
