import threading

from pyvex.lifting import register
from pyvex.lifting.util import GymratLifter
from . import instr_mcf54455 as instrs


monkey_patch_lock = threading.Lock()


def monkey_patch():
    # already patched
    if not monkey_patch_lock.acquire(False):
        return

    from pyvex.lifting.util.vex_helper import IRSBCustomizer, mkbinop, mkunop
    from pyvex.lifting.util.syntax_wrapper import (
        VexValue, vvifyresults, checkparams)

    from pyvex.lifting.util import Type

    IRSBCustomizer.op_sar = mkbinop('Iop_Sar{arg_t[0]}')
    IRSBCustomizer.op_clz = mkunop('Iop_Clz{arg_t[0]}')

    @checkparams(rhstype=Type.int_8)
    @vvifyresults
    def __rshift__(self, right):
        if self._is_signed:
            return self.irsb_c.op_sar(self.rdt, right.rdt)
        else:
            return self.irsb_c.op_shr(self.rdt, right.rdt)

    VexValue.__rshift__ = __rshift__

    @checkparams()
    @vvifyresults
    def clz(self):
        return self.irsb_c.op_clz(self.rdt)

    VexValue.clz = clz

    @checkparams(rhstype=Type.int_8)
    def bit(self, bit):
        return (self >> bit).cast_to(Type.int_1)

    VexValue.bit = bit

    from claripy.ast import BV
    from angr.engines.vex.irop import operations

    operations['Iop_DivS32']._calculate = lambda args: BV.SDiv(*args)

    import copy
    from pyvex.stmt import LoadG, StoreG

    def loadg(self, guard, cvt, addr, ty, alt):
        tmp = self._add_tmp(ty)
        self._append_stmt(LoadG(self.arch.memory_endness, cvt, tmp,
                                copy.copy(addr), copy.copy(alt),
                                copy.copy(guard)))
        return self._rdtmp(tmp)

    IRSBCustomizer.loadg = loadg

    def storeg(self, guard, addr, expr):
        self._append_stmt(StoreG(self.arch.memory_endness, copy.copy(addr),
                                 copy.copy(expr), copy.copy(guard)))

    IRSBCustomizer.storeg = storeg

    # The additional cast makes no sense
    def mkcmpop(fstring_fragment, signedness=''):
        def cmpop(self, expr_a, expr_b):
            fstring = 'Iop_Cmp%s{arg_t[0]}%s' % (fstring_fragment, signedness)
            return mkbinop(fstring)(self, expr_a, expr_b)
        return cmpop

    IRSBCustomizer.op_cmp_eq = mkcmpop('EQ')
    IRSBCustomizer.op_cmp_ne = mkcmpop('NE')
    IRSBCustomizer.op_cmp_slt = mkcmpop('LT', 'S')
    IRSBCustomizer.op_cmp_sle = mkcmpop('LE', 'S')
    IRSBCustomizer.op_cmp_ult = mkcmpop('LT', 'U')
    IRSBCustomizer.op_cmp_ule = mkcmpop('LE', 'U')
    IRSBCustomizer.op_cmp_sge = mkcmpop('GE', 'S')
    IRSBCustomizer.op_cmp_uge = mkcmpop('GE', 'U')
    IRSBCustomizer.op_cmp_sgt = mkcmpop('GT', 'S')
    IRSBCustomizer.op_cmp_ugt = mkcmpop('GT', 'U')

    from angr import sim_options as o
    from angr.engines.vex.expressions.const import translate_irconst
    from angr.engines.vex.irop import translate
    import claripy
    from pyvex.const import vex_int_class
    from pyvex.expr import Const
    old_op_generic = IRSBCustomizer.op_generic
    fake_state = type('fake state', (), {'solver': claripy, 'options': {
        o.EXTENDED_IROP_SUPPORT,
        o.SUPPORT_FLOATING_POINT,
    }})()
    simple_solver = claripy.Solver()

    def op_generic(self, Operation, op_generator):
        orig_instance = old_op_generic(self, Operation, op_generator)

        def instance(*args):
            rdtmp = orig_instance(*args)

            if not all(arg.tag == 'Iex_Const' for arg in args):
                return rdtmp

            s = self.irsb.statements.pop()
            assert s.tag == 'Ist_WrTmp'
            assert s.tmp == rdtmp.tmp

            args = [translate_irconst(fake_state, arg.con) for arg in s.data.args]
            res = translate(fake_state, s.data.op, args)

            return Const(vex_int_class(res.size())(simple_solver.eval(res, 1)[0]))

        return instance

    IRSBCustomizer.op_generic = op_generic


class LifterMCF54455(GymratLifter):
    # The default behavior of GymratLifter works here.
    # We just grab all the instruction classes out of the other file.
    instrs = [v for k, v in instrs.__dict__.items()
              if k.startswith('Instruction_')]

    def lift(self, *args, **kwargs):
        monkey_patch()
        super().lift(*args, **kwargs)

    def _decode_next_instruction(self, addr):
        # Optimization: because we have so many instructions to match, at least
        # make sure bin_format is matched before we go to slow path
        sizes = {}
        real_instrs = self.instrs
        self.instrs = []
        try:
            for possible_instr in real_instrs:
                try:
                    match_bin_format = possible_instr.match_bin_format
                except AttributeError:
                    def closure():
                        import bitstring

                        length = len(possible_instr.bin_format)
                        if self.arch.instruction_endness == 'Iend_LE':
                            peektyp = f'uintle:{length}'
                        else:
                            peektyp = f'uintbe:{length}'

                        mask = match = 0
                        for c in possible_instr.bin_format:
                            mask *= 2
                            match *= 2

                            if c in '01':
                                mask += 1
                                if c == '1':
                                    match += 1

                        @classmethod
                        def match_bin_format(cls, bitstrm, sizes):
                            try:
                                bits = sizes[length]
                            except KeyError:
                                try:
                                    bits = bitstrm.peek(peektyp)
                                except bitstring.ReadError as e:
                                    bits = e
                                sizes[length] = bits

                            if isinstance(bits, Exception):
                                return False

                            return bits & mask == match

                        return match_bin_format

                    match_bin_format = closure()

                    possible_instr.match_bin_format = match_bin_format

                    # rebind to class
                    match_bin_format = possible_instr.match_bin_format

                if match_bin_format(self.bitstrm, sizes):
                    self.instrs.append(possible_instr)

            return super()._decode_next_instruction(addr)
        finally:
            del self.instrs


register(LifterMCF54455, 'MCF54455')
