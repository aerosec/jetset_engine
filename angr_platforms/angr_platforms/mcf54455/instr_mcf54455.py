import abc
import bitstring
import contextlib
import functools

from pyvex.lifting.util.syntax_wrapper import VexValue
from pyvex.lifting.util import JumpKind, ParseError, Type
from pyvex.lifting.util import Instruction as BaseInstruction
from pyvex.const import get_type_size

from .arch_mcf54455 import ArchMCF54455

Mode = ArchMCF54455.Mode

BOOL_TYPE = Type.int_1
BYTE_TYPE = Type.int_8
WORD_TYPE = Type.int_16
LONG_TYPE = Type.int_32

CARRY_BIT_IND = 0
OVERFLOW_BIT_IND = 1
ZERO_BIT_IND = 2
NEGATIVE_BIT_IND = 3
EXTEND_BIT_IND = 4

SUPERVISOR_BIT_IND = 13


def bits_to_signed_int(s):
    return bitstring.Bits(bin=s).int


def read_only(*args, **kwargs):
    raise Exception('Read-only addressing mode')


@contextlib.contextmanager
def signedness(lst, signed):
    lst = list(lst)
    old_signed = [x._is_signed for x in lst]
    for x in lst:
        x._is_signed = signed

    try:
        yield
    finally:
        for x, old in zip(lst, old_signed):
            x._is_signed = old


class InstructionUtils(BaseInstruction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.commit_func = None

    # Why is it not VexValue?
    def itevv(self, cond, t, f):
        assert cond.width == 1
        assert t.width == f.width, f'{t.width} != {f.width}'

        try:
            return t if cond.value else f
        except ValueError:
            return VexValue(self.irsb_c, self.ite(cond, t, f))

    def put_conditional(self, cond, valiftrue, valiffalse, reg):
        val = self.itevv(cond, valiftrue, valiffalse)
        self.put(val, reg)

    def compute_result(self, *args):
        return

    def commit_result(self, res):
        if self.commit_func is not None:
            self.commit_func(res)

    def read_word(self, bitstrm):
        self.bitwidth += 16
        return bitstrm.read('bin:16')

    def read_dword(self, bitstrm):
        self.bitwidth += 32
        return bitstrm.read('bin:32')


class LiftHooks(BaseInstruction):
    def pre_lift(self):
        pass

    def post_lift(self):
        pass

    def lift(self, *args, **kwargs):
        super().lift(*args, **kwargs)
        self.post_lift()

    def mark_instruction_start(self):
        super().mark_instruction_start()
        self.pre_lift()


class CacheRegisters(LiftHooks):
    def pre_lift(self):
        super().pre_lift()
        self.cached_registers = {}

    def post_lift(self):
        super().post_lift()
        for reg in list(self.cached_registers):
            self.cache_register_release(reg)

    def get(self, reg, ty):
        if reg not in self.cached_registers:
            return super().get(reg, ty)

        if not self.cached_registers[reg]:
            self.cached_registers[reg] = (False, super().get(reg, ty))

        return self.cached_registers[reg][1]

    def put(self, val, reg):
        if reg not in self.cached_registers:
            return super().put(val, reg)

        self.cached_registers[reg] = (True, val)

    def cache_register_add(self, reg):
        assert reg not in self.cached_registers
        self.cached_registers[reg] = None

    def cache_register_release(self, reg):
        if self.cached_registers[reg] and self.cached_registers[reg][0]:
            super().put(self.cached_registers[reg][0], reg)
        del self.cached_registers[reg]

    @contextlib.contextmanager
    def cache_register(self, reg):
        self.cache_register_add(reg)
        try:
            yield
        finally:
            self.cache_register_release(reg)


class StackedCondition(LiftHooks, InstructionUtils):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cur_conds = []
        self.jmp_conds = []  # cur_conds without jmp applied
        self.jumps = []

    def is_reachable(self):
        if self.cur_conds is None:
            return False

        if self.cur_conds and self.cur_conds[-1] is None:
            return False

        return True

    def push_condition(self, cond):
        if not self.is_reachable():
            return

        assert cond.width == 1

        if self.cur_conds:
            cond &= self.cur_conds[-1]

        self.cur_conds.append(cond)
        self.jmp_conds.append(cond)

    def pop_condition(self):
        self.cur_conds.pop()
        self.jmp_conds.pop()

    @contextlib.contextmanager
    def If(self, cond):
        self.push_condition(cond)
        try:
            yield
        finally:
            self.pop_condition()

    def load(self, addr, ty, alt=0):
        if isinstance(alt, int):
            alt = self.constant(alt, ty)
        else:
            assert alt.ty == ty

        if not self.is_reachable():
            return alt

        if not self.cur_conds:
            return super().load(addr, ty)

        cvt, rty = {
            # TODO: ILGop_IdentV128
            Type.int_64: ('ILGop_Ident64', Type.int_64),
            Type.int_32: ('ILGop_Ident32', Type.int_32),
            Type.int_16: ('ILGop_16Uto32', Type.int_32),
            Type.int_8: ('ILGop_8Uto32', Type.int_32),
        }[ty]

        rdt = self.irsb_c.loadg(self.cur_conds[-1].rdt, cvt, addr.rdt, rty,
                                alt.cast_to(rty).rdt)
        return VexValue(self.irsb_c, rdt).cast_to(ty)

    def store(self, val, addr):
        if not self.is_reachable():
            return

        if not self.cur_conds:
            return super().store(val, addr)

        self.irsb_c.storeg(self.cur_conds[-1].rdt, addr.rdt, val.rdt)

    def put(self, val, reg):
        if not self.is_reachable():
            return

        if self.cur_conds:
            val = self.itevv(self.cur_conds[-1], val, self.get(reg, val.ty))

        super().put(val, reg)

    def put_unconditional(self, val, reg):
        super().put(val, reg)

    def put_conditional(self, cond, valiftrue, valiffalse, reg):
        val = self.itevv(cond, valiftrue, valiffalse)
        self.put(val, reg)

    def jump(self, cond, addr, jumpkind=JumpKind.Boring):
        if not self.is_reachable():
            return

        if cond:
            assert cond.width == 1
            try:
                if cond.value:
                    cond = None
                else:
                    return
            except ValueError:
                pass

        eff = cond
        if self.jmp_conds:
            eff = self.jmp_conds[-1] & cond if cond else self.jmp_conds[-1]

        # Load still happen even if jumped out.
        # if eff:
        #     try:
        #         addr.value
        #     except ValueError:
        #         pass
        #     else:
        #         # Speedy process conditional constant-target jumps
        #         ip_offset = self.arch.ip_offset
        #         self.irsb_c.add_exit(eff.rdt, addr.rdt, jumpkind, ip_offset)
        #         return

        self.jumps.append((eff, addr, jumpkind))

        if not eff:
            self.cur_conds = None
        elif not self.cur_conds:
            assert cond
            self.cur_conds = [~cond]
        else:
            negated = ~eff

            if cond:
                self.cur_conds = [negated] + \
                    [c & negated for c in self.cur_conds]
            else:
                self.cur_conds.pop()
                self.cur_conds = [negated] + \
                    [c & negated for c in self.cur_conds] + \
                    [None]

    def post_lift(self):
        super().post_lift()

        # HACK: In some cases, GymratLifter.lift will call our jump after we
        # have finished lifting. It should not conflict with our logic so
        # obey as upstream. To test this case, run smgr.step(num_inst=1)
        self.jump = super().jump

        ip_offset = self.arch.ip_offset

        has_conditional_boring = False

        # Process conditional constant-target jumps
        while self.jumps:
            try:
                self.jumps[0][1].value
            except ValueError:
                break
            else:
                if not self.jumps[0][0]:
                    break
                eff, addr, jumpkind = self.jumps.pop(0)
                if jumpkind == JumpKind.Boring:
                    has_conditional_boring = True
                self.irsb_c.add_exit(eff.rdt, addr.rdt, jumpkind, ip_offset)

        deftarget, defjmpkind = self.next_pc(), JumpKind.Boring

        if not self.jumps:
            if has_conditional_boring:
                self.irsb_c.irsb.jumpkind = defjmpkind
                self.irsb_c.irsb.next = deftarget.rdt
            return

        # Process catch-all jump, if any
        eff, addr, jumpkind = self.jumps.pop()
        if not eff:
            # Have conditional variable targets, need negation
            if self.jumps:
                deftarget, defjmpkind = addr, jumpkind
                eff, addr, jumpkind = self.jumps.pop()
            # Just set as default target
            else:
                self.irsb_c.irsb.next = addr.rdt
                self.irsb_c.irsb.jumpkind = jumpkind
                return

        jumped = eff

        # ITE the targets as a stack
        composite = addr
        while self.jumps:
            eff, addr, newjumpkind = self.jumps.pop()
            assert newjumpkind == jumpkind, 'Unsupported jumpkind mixture'

            jumped |= eff
            composite = self.itevv(eff, addr, composite)

        # This would have been the default target in an ideal VEX
        self.irsb_c.add_exit((~jumped).rdt, deftarget.rdt,
                             defjmpkind, ip_offset)

        self.irsb_c.irsb.jumpkind = jumpkind
        self.irsb_c.irsb.next = composite.rdt


class Instruction(StackedCondition, abc.ABC):
    def get_sr(self):
        return self.get('sr', WORD_TYPE)

    def get_sp(self):
        return self.get('sp', LONG_TYPE)

    def set_sp(self, value):
        return self.put(value, 'sp')

    def get_pc(self):
        return self.constant(self.addr + 2, LONG_TYPE)

    def next_pc(self):
        return self.constant(self.addr + self.bitwidth // 8, LONG_TYPE)

    def push(self, value):
        newsp = self.get_sp() - 4
        self.set_sp(newsp)
        self.store(value.cast_to(LONG_TYPE), newsp)

    def pop(self, ty):
        oldsp = self.get_sp()
        value = self.load(oldsp, ty)
        self.set_sp(oldsp + 4)
        return value

    def trap(self, vector, pc=None):
        if pc is None:
            pc = self.constant(self.addr, LONG_TYPE)

        self.put_unconditional(self.constant(vector, LONG_TYPE), 'trap_num')
        self.jump(None, pc, jumpkind=JumpKind.Syscall)

    class Lazy:
        def __init__(self, func):
            self.func = func

        def _do_lazy_evaluate(self):
            self.func = (lambda v: lambda: v)(self.func())
            return self.func()

        # Any operation done on 'Lazy' will collapse it.
        def __getattr__(self, name):
            self._do_lazy_evaluate()
            return getattr(self.func(), name)

        for _attr in {'__mod__', '__add__', '__eq__'}:
            def closure(_attr):
                def generated_function(self, *args, **kwargs):
                    from inspect import getattr_static

                    self._do_lazy_evaluate()
                    val = self.func()
                    # Do an instance binding
                    return getattr_static(type(val), _attr).__get__(
                        val, type(val))(*args, **kwargs)

                return generated_function

            locals()[_attr] = closure(_attr)

    def parse_eff(self, bitstrm, field, ty):
        if not callable(ty):
            ty = (lambda ty: lambda mode: ty)(ty)

        mode, reg = field[:3], field[3:]

        # parse_eff should be called in match_instruction phase.
        # Extensions should not be read until _extra_parsing phase.
        if mode == '000':
            mode = Mode.DREG_DIRECT_MODE
            ty = ty(mode)

            fetch = self.Lazy(lambda: lambda:
                              self.fetch_eff(reg, mode, None, ty))
        elif mode == '001':
            mode = Mode.AREG_DIRECT_MODE
            ty = ty(mode)

            if ty not in {LONG_TYPE, WORD_TYPE}:
                raise ParseError

            fetch = self.Lazy(lambda: lambda:
                              self.fetch_eff(reg, mode, None, ty))
        elif mode == '010':
            mode = Mode.AREG_INDIRECT_MODE
            ty = ty(mode)

            fetch = self.Lazy(lambda: lambda:
                              self.fetch_eff(reg, mode, None, ty))
        elif mode == '011':
            mode = Mode.AREG_INDIRECT_POSTINCREMENT_MODE
            ty = ty(mode)

            fetch = self.Lazy(lambda: lambda:
                              self.fetch_eff(reg, mode, None, ty))
        elif mode == '100':
            mode = Mode.AREG_INDIRECT_PREDECREMENT_MODE
            ty = ty(mode)

            fetch = self.Lazy(lambda: lambda:
                              self.fetch_eff(reg, mode, None, ty))
        elif mode == '101':
            mode = Mode.AREG_INDIRECT_DISPLACEMENT_MODE
            ty = ty(mode)

            def fetch():
                ext = self.read_word(bitstrm)
                return lambda: self.fetch_eff(reg, mode, ext, ty)

            fetch = self.Lazy(fetch)
        elif mode == '110':
            mode = Mode.AREG_INDIRECT_SCALED_INDEX_MODE
            ty = ty(mode)

            def fetch():
                ext = self.read_word(bitstrm)
                areg, regid, long, scale, zero, disp = \
                    ext[0], ext[1:4], ext[4], ext[5:7], ext[7], ext[8:]
                if long != '1' or zero != '0':
                    # HACK: Something is wrong with this instruction. We have
                    # messed up the internal state of bitstream. Should make
                    # sure no other instruction can match
                    raise ParseError

                return lambda: self.fetch_eff(reg, mode,
                                              (areg, regid, scale, disp), ty)

            fetch = self.Lazy(fetch)
        elif mode == '111' and reg == '010':
            mode = Mode.PC_INDIRECT_DISPLACEMENT_MODE
            ty = ty(mode)

            def fetch():
                ext = self.read_word(bitstrm)
                return lambda: self.fetch_eff(None, mode, ext, ty)

            fetch = self.Lazy(fetch)
        elif mode == '111' and reg == '011':
            mode = Mode.PC_INDIRECT_SCALED_INDEX_MODE
            ty = ty(mode)

            def fetch():
                ext = self.read_word(bitstrm)
                areg, regid, long, scale, zero, disp = \
                    ext[0], ext[1:4], ext[4], ext[5:7], ext[7], ext[8:]
                if long != '1' or zero != '0':
                    # ditto
                    raise ParseError

                return lambda: self.fetch_eff(None, mode,
                                              (areg, regid, scale, disp), ty)

            fetch = self.Lazy(fetch)
        elif mode == '111' and reg == '000':
            mode = Mode.ABSOLUTE_SHORT_ADDRESSING_MODE
            ty = ty(mode)

            def fetch():
                ext = self.read_word(bitstrm)
                return lambda: self.fetch_eff(None, mode, ext, ty)

            fetch = self.Lazy(fetch)
        elif mode == '111' and reg == '001':
            mode = Mode.ABSOLUTE_LONG_ADDRESSING_MODE
            ty = ty(mode)

            def fetch():
                ext = self.read_dword(bitstrm)
                return lambda: self.fetch_eff(None, mode, ext, ty)

            fetch = self.Lazy(fetch)
        elif mode == '111' and reg == '100':
            mode = Mode.IMMEDIATE_DATA
            ty = ty(mode)

            def fetch():
                if ty == LONG_TYPE:
                    ext = self.read_dword(bitstrm)
                else:
                    ext = self.read_word(bitstrm)

                return lambda: self.fetch_eff(None, mode, ext, ty)

            fetch = self.Lazy(fetch)
        else:
            raise ParseError

        ret = [mode, fetch]

        if not hasattr(self, '_lazy_parse_eff'):
            self._lazy_parse_eff = []
        self._lazy_parse_eff.append(fetch)

        return ret

    def _extra_parsing(self, data, bitstrm):
        try:
            super_extra_parsing = super()._extra_parsing
        except AttributeError:
            pass
        else:
            data = super_extra_parsing(data, bitstrm)

        if hasattr(self, '_lazy_parse_eff'):
            for k, v in sorted(
                filter(lambda item: item[1] in self._lazy_parse_eff,
                       data.items()),
                key=lambda item: self._lazy_parse_eff.index(item[1])
            ):
                if isinstance(v, self.Lazy):
                    data[k] = v._do_lazy_evaluate()

            del self._lazy_parse_eff

        return data

    def load_eff(self, addr, ty):
        return self.load(addr, ty)

    def fetch_eff(self, reg_num, mode, extension, ty):
        """
        Resolve the operand for register-based modes.
        :param reg_num: The Register Number
        :param mode: The Addressing Mode
        :param ty: The Type (byte or word)
        :return: The VexValue of the operand, and the writeout function, if any.
        """
        if mode == Mode.DREG_DIRECT_MODE:
            reg_name = ArchMCF54455.data_reg(reg_num)
            if ty == BYTE_TYPE:
                reg_name += '.b'
            elif ty == WORD_TYPE:
                reg_name += '.w'
            elif ty != LONG_TYPE:
                raise AttributeError

            readin = lambda: self.get(reg_name, ty)
            writeout = lambda v: self.put(v, reg_name)
        elif mode == Mode.AREG_DIRECT_MODE:
            reg_name = ArchMCF54455.address_reg(reg_num)

            readin = lambda: self.get(reg_name, LONG_TYPE).cast_to(ty)
            writeout = lambda v: self.put(v.cast_to(
                LONG_TYPE, signed=True), reg_name)
        elif mode == Mode.AREG_INDIRECT_MODE:
            reg_vv = self.get(ArchMCF54455.address_reg(reg_num), LONG_TYPE)

            readin = lambda: self.load_eff(reg_vv, ty)
            writeout = lambda v: self.store(v, reg_vv)
        elif mode == Mode.AREG_INDIRECT_POSTINCREMENT_MODE:
            reg_vv = self.get(ArchMCF54455.address_reg(reg_num), LONG_TYPE)

            readin = (lambda reg_vv: lambda: self.load_eff(reg_vv, ty))(reg_vv)
            writeout = (lambda reg_vv: lambda v: self.store(v, reg_vv))(reg_vv)

            reg_vv += get_type_size(ty) // 8
            self.put(reg_vv, ArchMCF54455.address_reg(reg_num))
        elif mode == Mode.AREG_INDIRECT_PREDECREMENT_MODE:
            reg_vv = self.get(ArchMCF54455.address_reg(reg_num), LONG_TYPE)
            reg_vv -= get_type_size(ty) // 8

            readin = lambda: self.load_eff(reg_vv, ty)
            writeout = lambda v: self.store(v, reg_vv)

            self.put(reg_vv, ArchMCF54455.address_reg(reg_num))
        elif mode == Mode.AREG_INDIRECT_DISPLACEMENT_MODE:
            reg_vv = self.get(ArchMCF54455.address_reg(reg_num), LONG_TYPE)

            disp = self.constant(int(extension, 2), WORD_TYPE)
            # FIXME: IDA says DEADBEEF is not what we expect
            addr_val = reg_vv + disp.cast_to(LONG_TYPE, signed=True)

            readin = lambda: self.load_eff(addr_val, ty)
            writeout = lambda v: self.store(v, addr_val)
        elif mode == Mode.AREG_INDIRECT_SCALED_INDEX_MODE:
            reg_vv = self.get(ArchMCF54455.address_reg(reg_num), LONG_TYPE)

            areg, regid, scale, disp = extension
            disp = self.constant(int(disp, 2), BYTE_TYPE)

            if areg == '0':
                regid = self.get(ArchMCF54455.data_reg(regid), LONG_TYPE)
            elif areg == '1':
                regid = self.get(ArchMCF54455.address_reg(regid), LONG_TYPE)
            else:
                raise AssertionError

            addr_val = reg_vv + disp.cast_to(LONG_TYPE, signed=True)

            if scale == '00':
                scale = 1
            elif scale == '01':
                scale = 2
            elif scale == '10':
                scale = 4
            elif scale == '11':
                scale = 8
            else:
                raise AssertionError

            addr_val += regid * scale

            readin = lambda: self.load_eff(addr_val, ty)
            writeout = lambda v: self.store(v, addr_val)
        elif mode == Mode.PC_INDIRECT_DISPLACEMENT_MODE:
            reg_vv = self.get_pc()

            disp = self.constant(int(extension, 2), WORD_TYPE)
            # FIXME: IDA says DEADBEEF is not what we expect
            addr_val = reg_vv + disp.cast_to(LONG_TYPE, signed=True)

            readin = lambda: self.load_eff(addr_val, ty)
            writeout = read_only
        elif mode == Mode.PC_INDIRECT_SCALED_INDEX_MODE:
            reg_vv = self.get_pc()

            areg, regid, scale, disp = extension
            disp = self.constant(int(disp, 2), BYTE_TYPE)

            if areg == '0':
                regid = self.get(ArchMCF54455.data_reg(regid), LONG_TYPE)
            elif areg == '1':
                regid = self.get(ArchMCF54455.address_reg(regid), LONG_TYPE)
            else:
                raise AssertionError

            addr_val = reg_vv + disp.cast_to(LONG_TYPE, signed=True)

            if scale == '00':
                scale = 1
            elif scale == '01':
                scale = 2
            elif scale == '10':
                scale = 4
            elif scale == '11':
                scale = 8
            else:
                raise AssertionError

            addr_val += regid * scale

            readin = lambda: self.load_eff(addr_val, ty)
            writeout = read_only
        elif mode == Mode.ABSOLUTE_SHORT_ADDRESSING_MODE:
            addr_val = self.constant(int(extension, 2), WORD_TYPE)
            addr_val = addr_val.cast_to(LONG_TYPE, signed=True)

            readin = lambda: self.load_eff(addr_val, ty)
            writeout = lambda v: self.store(v, addr_val)
        elif mode == Mode.ABSOLUTE_LONG_ADDRESSING_MODE:
            addr_val = self.constant(int(extension, 2), LONG_TYPE)
            # addr_val = addr_val.cast_to(LONG_TYPE, signed=True)

            readin = lambda: self.load_eff(addr_val, ty)
            writeout = lambda v: self.store(v, addr_val)
        elif mode == Mode.IMMEDIATE_DATA:
            if ty == LONG_TYPE:
                val = self.constant(int(extension, 2), LONG_TYPE)
            else:
                val = self.constant(int(extension, 2), WORD_TYPE)
            readin = lambda: val.cast_to(ty)
            writeout = read_only
        else:
            raise Exception('Unknown mode found')
        return self.Lazy(readin), writeout

    def fetch_operands(self):
        try:
            operands = self._fetch_operands
        except AttributeError:
            return []
        else:
            operands = list(operands())

        for i, op in enumerate(operands):
            if isinstance(op, self.Lazy):
                operands[i] = op._do_lazy_evaluate()

        return operands

    def disassemble(self):
        class Shim:
            def __init__(self, val):
                self.val = val

            def cast_to(self, *args, **kwargs):
                return self

            def __mod__(self, right):
                if not isinstance(right, int):
                    return NotImplemented
                return self

            def __add__(self, right):
                if not isinstance(right, int):
                    return NotImplemented
                if not isinstance(self.val, int):
                    return NotImplemented
                return Shim(self.val + right)

        def get(reg, ty):
            return Shim(reg)

        def put(val, reg):
            return Shim(reg)

        def constant(val, ty):
            return Shim(val)

        def divide_by_zero_check(divisor):
            return divisor

        def get_extend():
            return Shim('extend')

        def set_sr(value):
            return Shim('sr')

        def fetch_eff(reg_num, mode, extension, ty):
            if mode == Mode.DREG_DIRECT_MODE:
                mnemonic = f'{ArchMCF54455.data_reg(reg_num)}'
            elif mode == Mode.AREG_DIRECT_MODE:
                mnemonic = f'{ArchMCF54455.address_reg(reg_num)}'
            elif mode == Mode.AREG_INDIRECT_MODE:
                mnemonic = f'({ArchMCF54455.address_reg(reg_num)})'
            elif mode == Mode.AREG_INDIRECT_POSTINCREMENT_MODE:
                mnemonic = f'({ArchMCF54455.address_reg(reg_num)})+'
            elif mode == Mode.AREG_INDIRECT_PREDECREMENT_MODE:
                mnemonic = f'-({ArchMCF54455.address_reg(reg_num)})'
            elif mode == Mode.AREG_INDIRECT_DISPLACEMENT_MODE:
                mnemonic = (f'{bits_to_signed_int(extension)}'
                            f'({ArchMCF54455.address_reg(reg_num)})')
            elif mode == Mode.AREG_INDIRECT_SCALED_INDEX_MODE:
                areg, regid, scale, disp = extension

                if areg == '0':
                    regid = ArchMCF54455.data_reg(regid)
                elif areg == '1':
                    regid = ArchMCF54455.address_reg(regid)
                else:
                    raise AssertionError

                if scale == '00':
                    scale = 1
                elif scale == '01':
                    scale = 2
                elif scale == '10':
                    scale = 4
                elif scale == '11':
                    scale = 8
                else:
                    raise AssertionError

                mnemonic = (f'{bits_to_signed_int(disp)}'
                            f'({ArchMCF54455.address_reg(reg_num)},'
                            f'{regid}*{scale})')
            elif mode == Mode.PC_INDIRECT_DISPLACEMENT_MODE:
                mnemonic = f'{bits_to_signed_int(extension)}(pc)'
            elif mode == Mode.PC_INDIRECT_SCALED_INDEX_MODE:
                areg, regid, scale, disp = extension

                if areg == '0':
                    regid = ArchMCF54455.data_reg(regid)
                elif areg == '1':
                    regid = ArchMCF54455.address_reg(regid)
                else:
                    raise AssertionError

                if scale == '00':
                    scale = 1
                elif scale == '01':
                    scale = 2
                elif scale == '10':
                    scale = 4
                elif scale == '11':
                    scale = 8
                else:
                    raise AssertionError

                mnemonic = (f'{bits_to_signed_int(disp)}'
                            f'(pc,{regid}*{scale})')
            elif mode == Mode.ABSOLUTE_SHORT_ADDRESSING_MODE:
                mnemonic = f'({hex(int(extension, 2))}).w'
            elif mode == Mode.ABSOLUTE_LONG_ADDRESSING_MODE:
                mnemonic = f'({hex(int(extension, 2))}).l'
            elif mode == Mode.IMMEDIATE_DATA:
                mnemonic = int(extension, 2)
            else:
                raise Exception('Unknown mode found')

            mnemonic = Shim(mnemonic)

            return mnemonic, lambda val: mnemonic

        self.get = get
        self.put = put
        self.constant = constant
        self.divide_by_zero_check = divide_by_zero_check
        self.get_extend = get_extend
        self.set_sr = set_sr
        self.fetch_eff = fetch_eff
        self.fetch_eff_write = fetch_eff

        def fetch_operands_wrapped():
            operands = self.fetch_operands()
            if isinstance(self, Extended):
                operands.pop()
            if isinstance(self, Arithmetic_NEG):
                operands.pop(0)
            return list(operands[::-1])

        try:
            has_reg = sum([
                'd' in self.data, 'a' in self.data, 'r' in self.data])
            assert has_reg <= 1
            has_reg = bool(has_reg)

            if not self.data or set(self.data.keys()) == {'o'}:
                # No data, don't bother
                operands = []
            elif 's' in self.data:
                if 'd' in self.data:
                    if isinstance(self, Instruction_MOVE):
                        operands = fetch_operands_wrapped()
                        assert len(operands) == 1
                        operands.append(self.commit_func)
                    elif isinstance(self, DyDx):
                        operands = fetch_operands_wrapped()
                        assert len(operands) == 2
                    else:
                        raise AssertionError
                else:
                    raise AssertionError
            elif 'I' in self.data:
                if not has_reg and 'e' not in self.data:
                    operands = fetch_operands_wrapped()
                    assert len(operands) == 1
                elif has_reg != ('e' in self.data):
                    operands = fetch_operands_wrapped()

                    if len(operands) == 1:
                        assert self.commit_func
                        operands.append(self.commit_func)

                    if isinstance(self, Instruction_MOVEM):
                        if self.data['o'] == '1':
                            operands = operands[::-1]

                    assert len(operands) == 2
                else:
                    raise NotImplementedError
            elif 'w' in self.data and self.data['d'] != self.data['w']:
                assert isinstance(self, REM_L)
                operands = fetch_operands_wrapped()
                assert len(operands) == 2
                operands.append(f'd{int(self.data["w"], 2)}')
            elif all(k in self.data for k in {'c', 'o', 't', 'd'}):
                assert isinstance(self, Instruction_Shift)
                operands = fetch_operands_wrapped()
                assert len(operands) == 2
            elif has_reg != ('e' in self.data):
                operands = fetch_operands_wrapped()
                if not operands and self.commit_func:
                    operands = [self.commit_func]

                assert len(operands) == 1

                if self.name in {'move', 'movec'}:
                    # Move to/from specific registers
                    assert self.commit_func
                    operands.append(self.commit_func)
            elif has_reg and 'e' in self.data:
                operands = fetch_operands_wrapped()
                if len(operands) == 1:
                    operands.append(self.commit_func)
                assert len(operands) == 2
            else:
                raise NotImplementedError

            def stringfy_operand(op):
                if callable(op):
                    op = op(None)
                if isinstance(op, Shim):
                    op = op.val
                if isinstance(op, int):
                    op = f'#{hex(op)}'
                assert isinstance(op, str)
                return op

            operands = list(map(stringfy_operand, operands))

            return self.addr, self.name, operands
        except (TypeError, AssertionError, NotImplementedError):
            raise NotImplementedError(self.name.upper(), self.data)
        finally:
            del self.get
            del self.put
            del self.constant
            del self.divide_by_zero_check
            del self.set_sr
            del self.get_extend
            del self.fetch_eff
            del self.fetch_eff_write


class IntegerInstruction(Instruction):
    # FLAGS
    def carry(self, *args):
        return None

    def overflow(self, *args):
        return None

    def zero(self, *args):
        return None

    def negative(self, *args):
        return None

    def extend(self, *args):
        return None

    # REGISTERS
    def get_ccr(self):
        return self.get('ccr', BYTE_TYPE)

    def set_ccr(self, value):
        return self.put(value, 'ccr')

    def get_carry(self):
        return self.get_ccr().bit(CARRY_BIT_IND)

    def get_overflow(self):
        return self.get_ccr().bit(OVERFLOW_BIT_IND)

    def get_zero(self):
        return self.get_ccr().bit(ZERO_BIT_IND)

    def get_negative(self):
        return self.get_ccr().bit(NEGATIVE_BIT_IND)

    def get_extend(self):
        return self.get_ccr().bit(EXTEND_BIT_IND)

    def compute_flags(self, *args):
        c = self.carry(*args)
        o = self.overflow(*args)
        z = self.zero(*args)
        n = self.negative(*args)
        x = self.extend(*args)
        self.set_flags(c, o, z, n, x)

    def set_flags(self, c, o, z, n, x):
        if not any((c, o, z, n, x)):
            return
        flags = [
            (c, CARRY_BIT_IND),
            (o, OVERFLOW_BIT_IND),
            (z, ZERO_BIT_IND),
            (n, NEGATIVE_BIT_IND),
            (x, EXTEND_BIT_IND),
        ]

        mask = ~0
        overlay = 0

        ccreg = self.get_ccr()

        for flag, offset in flags:
            if flag is not None:
                assert flag.width == 1
                mask &= ~(1 << offset)

                try:
                    flag.value
                except ValueError:
                    overlay |= flag.cast_to(ccreg.ty) << offset
                else:
                    overlay |= flag.value << offset

        ccreg = ccreg & mask | overlay
        self.set_ccr(ccreg)


class SupervisorInstruction(Instruction):
    def pre_lift(self):
        super().pre_lift()

        supervisor = self.get_sr().bit(SUPERVISOR_BIT_IND)
        with self.If(~supervisor):
            self.trap(8)

        self.sr_set = False

    def set_sr(self, value):
        # Due to sp swapping, do not allow multiple sets per instruction
        if self.sr_set:
            raise NotImplementedError
        self.sr_set = True

        with self.If(~value.bit(SUPERVISOR_BIT_IND)):
            usp = self.get('other_a7', LONG_TYPE)
            ssp = self.get('a7', LONG_TYPE)
            self.put(usp, 'a7')
            self.put(ssp, 'other_a7')

        return self.put(value, 'sr')


class EMACInstruction(Instruction):
    pass


class ParseEff(IntegerInstruction):
    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)
        data['E'], data['e'] = self.parse_eff(bitstrm, data['e'], LONG_TYPE)


class LoadEffectiveAddress(ParseEff):
    def load_eff(self, addr, ty):
        return addr.cast_to(ty)

    def fetch_eff_write(self, *args):
        readin, writeout = super().fetch_eff(*args)
        return None, writeout

    def fetch_eff(self, *args):
        readin, writeout = super().fetch_eff(*args)
        return readin, read_only

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        if data['E'] in {
            Mode.DREG_DIRECT_MODE,
            Mode.AREG_DIRECT_MODE,
            Mode.AREG_INDIRECT_PREDECREMENT_MODE,
            Mode.AREG_INDIRECT_POSTINCREMENT_MODE,
            Mode.IMMEDIATE_DATA,
        }:
            raise ParseError

    def compute_result(self, x):
        return x


class MemoizeCC(CacheRegisters, IntegerInstruction):
    def memoize_to_attr(attr):
        def outer(f):
            @functools.wraps(f)
            def inner(self):
                try:
                    return getattr(self, attr)
                except AttributeError:
                    r = f(self)
                    setattr(self, attr, r)
                    return r

            return inner
        return outer

    @memoize_to_attr('_carry')
    def get_carry(self):
        return super().get_carry()

    @memoize_to_attr('_overflow')
    def get_overflow(self):
        return super().get_overflow()

    @memoize_to_attr('_zero')
    def get_zero(self):
        return super().get_zero()

    @memoize_to_attr('_negative')
    def get_negative(self):
        return super().get_negative()

    @memoize_to_attr('_extend')
    def get_extend(self):
        return super().get_extend()

    del memoize_to_attr


class ParseCond(MemoizeCC):
    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        if data['o'] == '0100':
            name = 'cc'
            cond = lambda: ~self.get_carry()
        elif data['o'] == '0101':
            name = 'cs'
            cond = lambda: self.get_carry()
        elif data['o'] == '0111':
            name = 'eq'

            cond = lambda: self.get_zero()
        elif data['o'] == '0001':
            name = 'f'
            cond = lambda: self.constant(0, BOOL_TYPE)
        elif data['o'] == '1100':
            name = 'ge'
            cond = lambda: (
                (self.get_negative() & self.get_overflow()) |
                (~self.get_negative() & ~self.get_overflow())
            )
        elif data['o'] == '1110':
            name = 'gt'
            cond = lambda: (
                (self.get_negative() & self.get_overflow() & ~self.get_zero()) |
                (~self.get_negative() & ~self.get_overflow() & ~self.get_zero())
            )
        elif data['o'] == '0010':
            name = 'hi'
            cond = lambda: ~self.get_carry() & ~self.get_zero()
        elif data['o'] == '1111':
            name = 'le'
            cond = lambda: (
                self.get_zero() |
                (self.get_negative() & ~self.get_overflow()) |
                (~self.get_negative() & self.get_overflow())
            )
        elif data['o'] == '0011':
            name = 'ls'
            cond = lambda: self.get_carry() | self.get_zero()
        elif data['o'] == '1101':
            name = 'lt'
            cond = lambda: (
                (self.get_negative() & ~self.get_overflow()) |
                (~self.get_negative() & self.get_overflow())
            )
        elif data['o'] == '1011':
            name = 'mi'
            cond = lambda: self.get_negative()
        elif data['o'] == '0110':
            name = 'ne'
            cond = lambda: ~self.get_zero()
        elif data['o'] == '1010':
            name = 'pl'
            cond = lambda: ~self.get_negative()
        elif data['o'] == '0000':
            name = 't'
            cond = lambda: self.constant(1, BOOL_TYPE)
        elif data['o'] == '1000':
            name = 'vc'
            cond = lambda: ~self.get_overflow()
        elif data['o'] == '1001':
            name = 'vs'
            cond = lambda: self.get_overflow()
        else:
            raise ParseError

        def cond_wrapper():
            with self.cache_register('ccr'):
                return cond()

        self.name = self.name.replace('cc', name)
        data['o'] = data['o'], cond_wrapper


class CcFromFirst(IntegerInstruction):
    def carry(self, x, *args):
        return self.constant(0, BOOL_TYPE)

    def overflow(self, x, *args):
        return self.constant(0, BOOL_TYPE)

    def zero(self, x, *args):
        return x == 0

    def negative(self, x, *args):
        return x.bit(x.width - 1)


class OverrideNoCc(IntegerInstruction):
    def carry(self, *args):
        return None

    def overflow(self, *args):
        return None

    def zero(self, *args):
        return None

    def negative(self, *args):
        return None

    def extend(self, *args):
        return None


class NoResultCommit(IntegerInstruction):
    def commit_result(self, res):
        return


class ArithmeticLogic(IntegerInstruction):
    def zero(self, *args):
        retval = args[-1]
        return retval == 0

    def negative(self, *args):
        retval = args[-1]
        return retval.bit(retval.width - 1)

    def compute_result(self, *args):
        return functools.reduce(self._compute_result, args)


class Arithmetic(ArithmeticLogic):
    def carry(self, *args):
        args = list(args)
        args.pop()
        val = args.pop(0)
        res = []

        for arg in args:
            new = self._compute_result(val, arg)
            res.append(self._carry(val, arg, new))
            val = new

        return functools.reduce(lambda x, y: x | y, res)

    def overflow(self, *args):
        args = list(args)
        args.pop()
        val = args.pop(0)
        res = []

        for arg in args:
            new = self._compute_result(val, arg)
            res.append(self._overflow(val, arg, new))
            val = new

        return functools.reduce(lambda x, y: x | y, res)

    def extend(self, *args):
        return self.carry(*args)


class Logic(ArithmeticLogic):
    def carry(self, *args):
        return self.constant(0, BOOL_TYPE)

    def overflow(self, *args):
        return self.constant(0, BOOL_TYPE)


class QuickInstruction(ParseEff, ArithmeticLogic):
    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        if data['E'] in {
            Mode.IMMEDIATE_DATA,
            Mode.PC_INDIRECT_DISPLACEMENT_MODE,
            Mode.PC_INDIRECT_SCALED_INDEX_MODE,
        }:
            raise ParseError

    def _fetch_operands(self):
        dest, self.commit_func = self.data['e']()
        if self.data['I'] == '000':
            imm = self.constant(8, LONG_TYPE)
        else:
            imm = self.constant(int(self.data['I'], 2), LONG_TYPE)

        return [dest, imm]


class ImmediateInstruction(ArithmeticLogic):
    def _fetch_operands(self):
        dreg, self.commit_func = self.fetch_eff(
            self.data['d'], Mode.DREG_DIRECT_MODE, None, LONG_TYPE)
        imm = self.constant(int(self.data['I'], 2), LONG_TYPE)

        return [dreg, imm]

    def _extra_parsing(self, data, bitstrm):
        data['I'] = self.read_dword(bitstrm)
        return super()._extra_parsing(data, bitstrm)


class BinaryArithmeticLogic(ParseEff):
    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)
        dreg = data['d']
        data['d'] = lambda: self.fetch_eff(
            dreg, Mode.DREG_DIRECT_MODE, None, LONG_TYPE)


class OpmodeDeterminesDirection(BinaryArithmeticLogic):
    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)
        if data['o'] == '110':
            if data['E'] in {
                Mode.DREG_DIRECT_MODE,
                Mode.AREG_DIRECT_MODE,
                Mode.IMMEDIATE_DATA,
                Mode.PC_INDIRECT_DISPLACEMENT_MODE,
                Mode.PC_INDIRECT_SCALED_INDEX_MODE,
            }:
                raise ParseError
        elif data['o'] != '010':
            raise ParseError

    def _fetch_operands(self):
        if self.data['o'] == '010':
            dest, self.commit_func = self.data['d']()
            src, _ = self.data['e']()
        elif self.data['o'] == '110':
            dest, self.commit_func = self.data['e']()
            src, _ = self.data['d']()
        else:
            raise AssertionError

        return [dest, src]


class OpmodeDeterminesDirectionNoAreg(OpmodeDeterminesDirection):
    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)
        if data['o'] == '010':
            if data['E'] in {
                Mode.AREG_DIRECT_MODE,
            }:
                raise ParseError


class EayDx(ParseEff):
    def _fetch_operands(self):
        dest, self.commit_func = self.fetch_eff(
            self.data['d'], Mode.DREG_DIRECT_MODE, None, LONG_TYPE)
        src, _ = self.data['e']()

        return [dest, src]


class EayAx(ParseEff):
    def _fetch_operands(self):
        dest, self.commit_func = self.fetch_eff(
            self.data['a'], Mode.AREG_DIRECT_MODE, None, LONG_TYPE)
        src, _ = self.data['e']()

        return [dest, src]


class DyEax(ParseEff):
    def _fetch_operands(self):
        dest, self.commit_func = self.data['e']()
        src, _ = self.fetch_eff(
            self.data['d'], Mode.DREG_DIRECT_MODE, None, LONG_TYPE)

        return [dest, src]


class DyDx(IntegerInstruction):
    def _fetch_operands(self):
        dest, self.commit_func = self.fetch_eff(
            self.data['d'], Mode.DREG_DIRECT_MODE, None, LONG_TYPE)
        src, _ = self.fetch_eff(
            self.data['s'], Mode.DREG_DIRECT_MODE, None, LONG_TYPE)

        return [dest, src]


class Extended(IntegerInstruction):
    def _fetch_operands(self):
        return [*super()._fetch_operands(),
                self.get_extend().cast_to(LONG_TYPE)]

    def zero(self, *args):
        retval = args[-1]
        return self.itevv(retval == 0,
                          self.get_zero(), self.constant(0, BOOL_TYPE))


class Unary(IntegerInstruction):
    def _fetch_operands(self):
        dest, self.commit_func = self.fetch_eff(
            self.data['d'], Mode.DREG_DIRECT_MODE, None, LONG_TYPE)

        return [dest]


class BitOp(IntegerInstruction):
    def type(self, mode):
        if mode in {Mode.AREG_DIRECT_MODE, Mode.DREG_DIRECT_MODE}:
            return LONG_TYPE
        return BYTE_TYPE

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)
        data['E'], data['e'] = self.parse_eff(bitstrm, data['e'], self.type)

    def compute_result(self, x, bitnum):
        return

    def zero(self, x, bitnum, retval):
        return ~x.bit(bitnum)


class BitOpStatic(BitOp):
    def _fetch_operands(self):
        x, self.commit_func = self.data['e']()
        bitnum = self.constant(int(self.data['I'], 2), WORD_TYPE)
        bitnum %= get_type_size(self.type(self.data['E']))
        bitnum = bitnum.cast_to(BYTE_TYPE)
        return [x, bitnum]

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        if data['E'] in {
            Mode.AREG_DIRECT_MODE,
            Mode.AREG_INDIRECT_SCALED_INDEX_MODE,
            Mode.ABSOLUTE_SHORT_ADDRESSING_MODE,
            Mode.ABSOLUTE_LONG_ADDRESSING_MODE,
            Mode.IMMEDIATE_DATA,
            Mode.PC_INDIRECT_DISPLACEMENT_MODE,
            Mode.PC_INDIRECT_SCALED_INDEX_MODE,
        }:
            raise ParseError


class BitOpDynamic(BitOp):
    def _fetch_operands(self):
        x, self.commit_func = self.data['e']()
        bitnum, _ = self.fetch_eff(
            self.data['d'], Mode.DREG_DIRECT_MODE, None, LONG_TYPE)
        bitnum %= get_type_size(self.type(self.data['E']))
        bitnum = bitnum.cast_to(BYTE_TYPE)
        return [x, bitnum]

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        if data['E'] in {
            Mode.AREG_DIRECT_MODE,
            Mode.IMMEDIATE_DATA,
        }:
            raise ParseError


class JumpingEffAddr(LoadEffectiveAddress):
    def _fetch_operands(self):
        addr, _ = self.data['e']()
        return [addr]


class JumpingDisplacement(IntegerInstruction):
    def _extra_parsing(self, data, bitstrm):
        if data['I'] == '00000000':
            data['I'] = self.read_word(bitstrm)
        elif data['I'] == '11111111':
            data['I'] = self.read_dword(bitstrm)

        return super()._extra_parsing(data, bitstrm)

    def _fetch_operands(self):
        return [self.get_pc() + bits_to_signed_int(self.data['I'])]


class Arithmetic_ADD(Arithmetic):
    def _compute_result(self, x, y):
        return x + y

    def _carry(self, x, y, r):
        return (r < x) | (r < y)

    def _overflow(self, x, y, r):
        bitnum = r.width - 1
        return ((y.bit(bitnum) ^ ~x.bit(bitnum)) &
                (r.bit(bitnum) ^ y.bit(bitnum)))


class Arithmetic_SUB(Arithmetic):
    def _compute_result(self, x, y):
        return x - y

    def _carry(self, x, y, r):
        with signedness([x, y], False):
            return y > x

    def _overflow(self, x, y, r):
        bitnum = r.width - 1
        return ((y.bit(bitnum) ^ x.bit(bitnum)) &
                (r.bit(bitnum) ^ ~y.bit(bitnum)))


class Arithmetic_NEG(Arithmetic_SUB):
    def _fetch_operands(self):
        return [self.constant(0, LONG_TYPE),
                *super()._fetch_operands()]


class BitOp_BCHG(BitOp):
    def compute_result(self, x, bitnum):
        return x ^ (self.constant(1, x.ty) << bitnum)


class BitOp_BCLR(BitOp):
    def compute_result(self, x, bitnum):
        return x & ~(self.constant(1, x.ty) << bitnum)


class BitOp_BSET(BitOp):
    def compute_result(self, x, bitnum):
        return x | (self.constant(1, x.ty) << bitnum)


class Logic_AND(Logic):
    def _compute_result(self, x, y):
        return x & y


class Logic_EOR(Logic):
    def _compute_result(self, x, y):
        return x ^ y


class Logic_OR(Logic):
    def _compute_result(self, x, y):
        return x | y


class Logic_NOT(Logic):
    def compute_result(self, x):
        return ~x


class MUL_DIV_REM_L(EayDx):
    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        if data['E'] in {
            Mode.AREG_DIRECT_MODE,
            Mode.AREG_INDIRECT_SCALED_INDEX_MODE,
            Mode.ABSOLUTE_SHORT_ADDRESSING_MODE,
            Mode.ABSOLUTE_LONG_ADDRESSING_MODE,
            Mode.IMMEDIATE_DATA,
            Mode.PC_INDIRECT_DISPLACEMENT_MODE,
            Mode.PC_INDIRECT_SCALED_INDEX_MODE,
        }:
            raise ParseError


# For some reason, MULU looks more like a logic instruction than an arithmetic
class Logic_MULU(Logic):
    signed = False

    def _compute_result(self, x, y):
        with signedness([x, y], False):
            return x * y


class Logic_MULS(Logic):
    signed = True

    def _compute_result(self, x, y):
        with signedness([x, y], True):
            return (x * y).cast_to(LONG_TYPE, signed=True)


class DIV_REM(ArithmeticLogic):
    def _fetch_operands(self):
        x, y = super()._fetch_operands()
        return x, self.divide_by_zero_check(y)

    def divide_by_zero_check(self, divisor):
        divide_by_zero = divisor == 0

        with self.If(divide_by_zero):
            self.trap(5)

        return self.itevv(
            divide_by_zero, self.constant(1, divisor.ty), divisor)

    def overflow(self, x, y, r):
        # FIXME: How do you overflow a division? Smallest negative / -1?
        # Only in signed mode?

        if self.signed:
            return ((x ^ (1 << (x.width - 1))) == 0) & (y == -1)
        else:
            return self.constant(0, BOOL_TYPE)

    def zero(self, *args):
        return self.itevv(self.overflow(*args),
                          self.constant(0, BOOL_TYPE),
                          super().zero(*args))

    def negative(self, *args):
        return self.itevv(self.overflow(*args),
                          self.constant(0, BOOL_TYPE),
                          super().negative(*args))

    def carry(self, *args):
        return self.constant(0, BOOL_TYPE)

    def commit_result(self, res):
        with self.If(~self.overflow(
                *self.stored_operands, self.stored_result)):
            super().commit_result(res)


class DIV_L(DIV_REM, MUL_DIV_REM_L):
    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        if data['w'] != data['d']:
            raise ParseError


class REM_L(DIV_REM, MUL_DIV_REM_L):
    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        if data['w'] == data['d']:
            raise ParseError

    def commit_result(self, res):
        _, self.commit_func = self.fetch_eff(
            self.data['w'], Mode.DREG_DIRECT_MODE, None, LONG_TYPE)
        super().commit_result(self._compute_remainder())


class DIV_W_UHALF(IntegerInstruction):
    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)
        data['E'], data['e'] = self.parse_eff(bitstrm, data['e'], WORD_TYPE)

        if data['E'] in {
            Mode.AREG_DIRECT_MODE,
        }:
            raise ParseError

    def _fetch_operands(self):
        dest, self.commit_func = self.fetch_eff(
            self.data['d'], Mode.DREG_DIRECT_MODE, None, LONG_TYPE)
        src, _ = self.data['e']()
        src = src.cast_to(LONG_TYPE, signed=self.signed)

        return [dest, src]


class DIV_W(DIV_REM, DIV_W_UHALF):
    def compute_result(self, *args):
        self.r_uncasted = super().compute_result(*args)
        self.stored_result = self.r_uncasted.cast_to(WORD_TYPE)
        return self.stored_result

    def commit_result(self, res):
        super().commit_result(
            res.cast_to(LONG_TYPE) |
            self._compute_remainder().cast_to(LONG_TYPE) << 16)

    def overflow(self, x, y, r):
        if self.signed:
            return super().overflow(x, y, r) | (
                r.cast_to(LONG_TYPE, signed=True) != self.r_uncasted)
        else:
            with signedness([self.r_uncasted], False):
                return super().overflow(x, y, r) | (
                    self.r_uncasted > 0xFFFF)


class MUL_W(IntegerInstruction):
    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)
        data['E'], data['e'] = self.parse_eff(bitstrm, data['e'], WORD_TYPE)

        if data['E'] in {
            Mode.AREG_DIRECT_MODE,
        }:
            raise ParseError

    def _fetch_operands(self):
        dest, _ = self.fetch_eff(
            self.data['d'], Mode.DREG_DIRECT_MODE, None, WORD_TYPE)
        _, self.commit_func = self.fetch_eff(
            self.data['d'], Mode.DREG_DIRECT_MODE, None, LONG_TYPE)
        src, _ = self.data['e']()
        dest = dest.cast_to(LONG_TYPE, signed=self.signed)
        src = src.cast_to(LONG_TYPE, signed=self.signed)

        return [dest, src]


class Op_DIVU(ArithmeticLogic):
    signed = False

    def compute_result(self, x, y):
        self.stored_operands = x, y

        with signedness([x, y], False):
            self.stored_result = x // y

        return self.stored_result

    def _compute_remainder(self):
        x, y = self.stored_operands

        with signedness([x, y], False):
            return x % y


class Op_DIVS(ArithmeticLogic):
    signed = True

    def compute_result(self, x, y):
        self.stored_operands = x, y

        with signedness([x, y], True):
            self.stored_result = x // y

        return self.stored_result

    def _compute_remainder(self):
        x, y = self.stored_operands
        r = getattr(self, 'r_uncasted', self.stored_result)

        with signedness([x, y, r], True):
            return x - (r * y).cast_to(x.ty)


class Instruction_ORI(ImmediateInstruction, Logic_OR):
    bin_format = '0000000010000ddd'
    name = 'ori'


class Instruction_BITREV(Unary):
    bin_format = '0000000011000ddd'
    name = 'bitrev'

    def compute_result(self, x):
        x = ((x & 0x55555555) << 1) | ((x & 0xAAAAAAAA) >> 1)
        x = ((x & 0x33333333) << 2) | ((x & 0xCCCCCCCC) >> 2)
        x = ((x & 0x0F0F0F0F) << 4) | ((x & 0xF0F0F0F0) >> 4)
        x = ((x & 0x00FF00FF) << 8) | ((x & 0xFF00FF00) >> 8)
        x = ((x & 0x0000FFFF) << 16) | ((x & 0xFFFF0000) >> 16)
        return x


class Instruction_BTST_Dynamic(BitOpDynamic):
    bin_format = '0000ddd100eeeeee'
    name = 'btst'


class Instruction_BCHG_Dynamic(BitOpDynamic, BitOp_BCHG):
    bin_format = '0000ddd101eeeeee'
    name = 'bchg'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        if data['E'] in {
            Mode.PC_INDIRECT_DISPLACEMENT_MODE,
            Mode.PC_INDIRECT_SCALED_INDEX_MODE,
        }:
            raise ParseError


class Instruction_BCLR_Dynamic(BitOpDynamic, BitOp_BCLR):
    bin_format = '0000ddd110eeeeee'
    name = 'bclr'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        if data['E'] in {
            Mode.PC_INDIRECT_DISPLACEMENT_MODE,
            Mode.PC_INDIRECT_SCALED_INDEX_MODE,
        }:
            raise ParseError


class Instruction_BSET_Dynamic(BitOpDynamic, BitOp_BSET):
    bin_format = '0000ddd111eeeeee'
    name = 'bset'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        if data['E'] in {
            Mode.PC_INDIRECT_DISPLACEMENT_MODE,
            Mode.PC_INDIRECT_SCALED_INDEX_MODE,
        }:
            raise ParseError


class Instruction_ANDI(ImmediateInstruction, Logic_AND):
    bin_format = '0000001010000ddd'
    name = 'andi'


class Instruction_BYTEREV(Unary):
    bin_format = '0000001011000ddd'
    name = 'byterev'

    def compute_result(self, x):
        x = ((x & 0x00FF00FF) << 8) | ((x & 0xFF00FF00) >> 8)
        x = ((x & 0x0000FFFF) << 16) | ((x & 0xFFFF0000) >> 16)
        return x


class Instruction_SUBI(ImmediateInstruction, Arithmetic_SUB):
    bin_format = '0000010010000ddd'
    name = 'subi'


class Instruction_FF1(Unary, CcFromFirst):
    bin_format = '0000010011000ddd'
    name = 'ff1'

    def compute_result(self, x):
        # VEX says clz of 0 is undefined
        clz = self.itevv(x != 0, x, self.constant(1, x.ty)).clz()
        return self.itevv(x != 0, clz, self.constant(x.width, x.ty))


class Instruction_ADDI(ImmediateInstruction, Arithmetic_ADD):
    bin_format = '0000011010000ddd'
    name = 'addi'


class Instruction_BTST_Static(BitOpStatic):
    bin_format = '0000100000eeeeee00000000IIIIIIII'
    name = 'btst'


class Instruction_BCHG_Static(BitOpStatic, BitOp_BCHG):
    bin_format = '0000100001eeeeee00000000IIIIIIII'
    name = 'bchg'


class Instruction_BCLR_Static(BitOpStatic, BitOp_BCLR):
    bin_format = '0000100010eeeeee00000000IIIIIIII'
    name = 'bclr'


class Instruction_BSET_Static(BitOpStatic, BitOp_BSET):
    bin_format = '0000100011eeeeee00000000IIIIIIII'
    name = 'bset'


class Instruction_EORI(ImmediateInstruction, Logic_EOR):
    bin_format = '0000101010000ddd'
    name = 'eori'


class Instruction_CMPI(Arithmetic_SUB):
    bin_format = '00001100oo000ddd'
    name = 'cmpi'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        try:
            self.name, data['t'] = {
                '00': ('cmpi.b', BYTE_TYPE),
                '01': ('cmpi.w', WORD_TYPE),
                '10': ('cmpi.l', LONG_TYPE),
            }[data['o']]
        except KeyError:
            raise ParseError

    def _extra_parsing(self, data, bitstrm):
        if data['t'] == LONG_TYPE:
            data['I'] = self.read_dword(bitstrm)
        else:
            data['I'] = self.read_word(bitstrm)

        return super()._extra_parsing(data, bitstrm)

    def _fetch_operands(self):
        dreg, _ = self.fetch_eff(
            self.data['d'], Mode.DREG_DIRECT_MODE, None, self.data['t'])

        if self.data['t'] == LONG_TYPE:
            imm = self.constant(int(self.data['I'], 2), LONG_TYPE)
        else:
            imm = self.constant(int(self.data['I'], 2), WORD_TYPE)
        imm = imm.cast_to(self.data['t'])

        return [dreg, imm]

    def extend(self, *args):
        return None


class Instruction_MOVE(CcFromFirst):
    bin_format = '00ooddddddssssss'
    name = 'move'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        try:
            self.name, data['t'] = {
                '01': ('move.b', BYTE_TYPE),
                '11': ('move.w', WORD_TYPE),
                '10': ('move.l', LONG_TYPE),
            }[data['o']]
        except KeyError:
            raise ParseError

        data['S'], data['s'] = self.parse_eff(bitstrm, data['s'], data['t'])
        data['D'], data['d'] = self.parse_eff(
            bitstrm, data['d'][3:] + data['d'][:3], data['t'])

        if data['D'] in {
            Mode.AREG_DIRECT_MODE,
            Mode.IMMEDIATE_DATA,
            Mode.PC_INDIRECT_DISPLACEMENT_MODE,
            Mode.PC_INDIRECT_SCALED_INDEX_MODE,
        }:
            raise ParseError

        if data['S'] in {
            Mode.AREG_INDIRECT_DISPLACEMENT_MODE,
            Mode.PC_INDIRECT_DISPLACEMENT_MODE,
        }:
            if data['D'] in {
                Mode.AREG_INDIRECT_SCALED_INDEX_MODE,
                Mode.ABSOLUTE_SHORT_ADDRESSING_MODE,
                Mode.ABSOLUTE_LONG_ADDRESSING_MODE,
            }:
                raise ParseError

        if data['S'] in {
            Mode.AREG_INDIRECT_SCALED_INDEX_MODE,
            Mode.PC_INDIRECT_SCALED_INDEX_MODE,
            Mode.ABSOLUTE_SHORT_ADDRESSING_MODE,
            Mode.ABSOLUTE_LONG_ADDRESSING_MODE,
            Mode.IMMEDIATE_DATA,
        }:
            if data['D'] in {
                Mode.AREG_INDIRECT_DISPLACEMENT_MODE,
                Mode.AREG_INDIRECT_SCALED_INDEX_MODE,
                Mode.ABSOLUTE_SHORT_ADDRESSING_MODE,
                Mode.ABSOLUTE_LONG_ADDRESSING_MODE,
            }:
                # ISA_B
                if not (
                    data['S'] == Mode.IMMEDIATE_DATA and
                    data['D'] == Mode.AREG_INDIRECT_DISPLACEMENT_MODE and
                    data['t'] in [BYTE_TYPE, WORD_TYPE]
                ):
                    raise ParseError

    def _fetch_operands(self):
        x, _ = self.data['s']()
        _, self.commit_func = self.data['d']()

        return [x]

    def compute_result(self, x):
        return x


class Instruction_STLDSR(SupervisorInstruction):
    bin_format = '01000000111001110100011011111100'
    name = 'stldsr'

    def _extra_parsing(self, data, bitstrm):
        data['I'] = self.read_word(bitstrm)
        return super()._extra_parsing(data, bitstrm)

    def _fetch_operands(self):
        imm = self.constant(int(self.data['I'], 2), WORD_TYPE)

        return [imm]

    def compute_result(self, newsr):
        self.push(self.get_sr())
        self.set_sr(newsr)


class Instruction_MOVEA(IntegerInstruction):
    bin_format = '00ooaaa001eeeeee'
    name = 'movea'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        try:
            self.name, data['t'] = {
                '11': ('movea.w', WORD_TYPE),
                '10': ('movea.l', LONG_TYPE),
            }[data['o']]
        except KeyError:
            raise ParseError

        data['E'], data['e'] = self.parse_eff(bitstrm, data['e'], data['t'])

    def _fetch_operands(self):
        x, _ = self.data['e']()
        _, self.commit_func = self.fetch_eff(
            self.data['a'], Mode.AREG_DIRECT_MODE, None, LONG_TYPE)

        return [x]

    def compute_result(self, x):
        return x.cast_to(LONG_TYPE, signed=True)


class Instruction_NEGX(Extended, Arithmetic_NEG, Unary):
    bin_format = '0100000010000ddd'
    name = 'negx'


class Instruction_MOVE_from_SR(SupervisorInstruction):
    bin_format = '0100000011000ddd'
    name = 'move'

    def _fetch_operands(self):
        _, self.commit_func = self.fetch_eff(
            self.data['d'], Mode.DREG_DIRECT_MODE, None, WORD_TYPE)

        return [self.get_sr()]

    def compute_result(self, sr):
        return sr


class Instruction_LEA(LoadEffectiveAddress):
    bin_format = '0100aaa111eeeeee'
    name = 'lea'

    def _fetch_operands(self):
        x, _ = self.data['e']()
        _, self.commit_func = self.fetch_eff_write(
            self.data['a'], Mode.AREG_DIRECT_MODE, None, LONG_TYPE)

        return [x]


class Instruction_CLR(CcFromFirst):
    bin_format = '01000010ooeeeeee'
    name = 'clr'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        try:
            self.name, data['t'] = {
                '00': ('clr.b', BYTE_TYPE),
                '01': ('clr.w', WORD_TYPE),
                '10': ('clr.l', LONG_TYPE),
            }[data['o']]
        except KeyError:
            raise ParseError

        data['E'], data['e'] = self.parse_eff(bitstrm, data['e'], data['t'])

    def _fetch_operands(self):
        _, self.commit_func = self.data['e']()

        return []

    def compute_result(self):
        return self.constant(0, self.data['t'])


class Instruction_MOVE_from_CCR(IntegerInstruction):
    bin_format = '0100001011000ddd'
    name = 'move'

    def _fetch_operands(self):
        _, self.commit_func = self.fetch_eff(
            self.data['d'], Mode.DREG_DIRECT_MODE, None, WORD_TYPE)

        return [self.get_ccr()]

    def compute_result(self, ccr):
        return ccr.cast_to(WORD_TYPE)


class Instruction_NEG(Arithmetic_NEG, Unary):
    bin_format = '0100010010000ddd'
    name = 'negx'

    def carry(self, *args):
        retval = args[-1]
        return retval != self.constant(0, retval.ty)


class Instruction_MOVE_to_CCR(IntegerInstruction):
    bin_format = '0100010011eeeeee'
    name = 'move'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)
        data['E'], data['e'] = self.parse_eff(bitstrm, data['e'], BYTE_TYPE)

        if not data['E'] in {
            Mode.DREG_DIRECT_MODE,
            Mode.IMMEDIATE_DATA,
        }:
            raise ParseError

    def _fetch_operands(self):
        newccr, _ = self.data['e']()
        self.commit_func = self.set_ccr

        return [newccr]

    def compute_result(self, ccr):
        return ccr


class Instruction_NOT(Unary, Logic_NOT):
    bin_format = '0100011010000ddd'
    name = 'not'


class Instruction_MOVE_to_SR(SupervisorInstruction):
    bin_format = '0100011011eeeeee'
    name = 'move'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)
        data['E'], data['e'] = self.parse_eff(bitstrm, data['e'], WORD_TYPE)

        if not data['E'] in {
            Mode.DREG_DIRECT_MODE,
            Mode.IMMEDIATE_DATA,
        }:
            raise ParseError

    def _fetch_operands(self):
        newsr, _ = self.data['e']()
        self.commit_func = self.set_sr

        return [newsr]

    def compute_result(self, sr):
        return sr


class Instruction_SWAP(Unary, Logic):
    bin_format = '0100100001000ddd'
    name = 'swap'

    def compute_result(self, x):
        x = ((x & 0x0000FFFF) << 16) | ((x & 0xFFFF0000) >> 16)
        return x


class Instruction_PEA(LoadEffectiveAddress):
    bin_format = '0100100001eeeeee'
    name = 'pea'

    def _fetch_operands(self):
        x, _ = self.data['e']()
        self.commit_func = self.push

        return [x]


class Instruction_EXT(CcFromFirst):
    bin_format = '0100100ooo000ddd'
    name = 'ext'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        try:
            self.name, data['ts'], data['td'] = {
                '010': ('ext.w', BYTE_TYPE, WORD_TYPE),
                '011': ('ext.l', WORD_TYPE, LONG_TYPE),
                '111': ('extb.l', BYTE_TYPE, LONG_TYPE),
            }[data['o']]
        except KeyError:
            raise ParseError

    def _fetch_operands(self):
        x, _ = self.fetch_eff(
            self.data['d'], Mode.DREG_DIRECT_MODE, None, self.data['ts'])
        _, self.commit_func = self.fetch_eff(
            self.data['d'], Mode.DREG_DIRECT_MODE, None, self.data['td'])

        return [x]

    def compute_result(self, x):
        return x.cast_to(self.data['td'], signed=True)


class Instruction_MOVEM(LoadEffectiveAddress):
    bin_format = '01001o0011eeeeee'
    name = 'movem'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        if data['E'] not in {
            Mode.AREG_INDIRECT_MODE,
            Mode.AREG_INDIRECT_DISPLACEMENT_MODE,
        }:
            raise ParseError

    def _extra_parsing(self, data, bitstrm):
        data['I'] = self.read_word(bitstrm)
        return super()._extra_parsing(data, bitstrm)

    def _fetch_operands(self):
        startaddr, _ = self.data['e']()
        # This is not a VexValue so we can keep code sane
        mask = int(self.data['I'], 2)

        return [startaddr, mask]

    def compute_result(self, addr, mask):
        for i in range(16):
            if mask & (1 << i):
                ad, num = divmod(i, 8)
                regname = ('a' if ad else 'd') + str(num)
                if self.data['o'] == '0':
                    self.store(self.get(regname, LONG_TYPE), addr)
                elif self.data['o'] == '1':
                    self.put(self.load(addr, LONG_TYPE), regname)
                else:
                    raise AssertionError

                addr += 4


class Instruction_TST(CcFromFirst):
    bin_format = '01001010ooeeeeee'
    name = 'tst'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        try:
            self.name, ty = {
                '00': ('tst.b', BYTE_TYPE),
                '01': ('tst.w', WORD_TYPE),
                '10': ('tst.l', LONG_TYPE),
                # The docs says 11 is okay, but it conflicts with other insn
                # '11': WORD_TYPE,
            }[data['o']]
        except KeyError:
            raise ParseError

        data['E'], data['e'] = self.parse_eff(bitstrm, data['e'], ty)

    def _fetch_operands(self):
        val, _ = self.data['e']()
        return [val]


class Instruction_TAS(CcFromFirst):
    bin_format = '0100101011eeeeee'
    name = 'tst'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        data['E'], data['e'] = self.parse_eff(bitstrm, data['e'], BYTE_TYPE)

        if data['E'] in {
            Mode.DREG_DIRECT_MODE,
            Mode.AREG_DIRECT_MODE,
            Mode.IMMEDIATE_DATA,
            Mode.PC_INDIRECT_DISPLACEMENT_MODE,
            Mode.PC_INDIRECT_SCALED_INDEX_MODE,
        }:
            raise ParseError

    def _fetch_operands(self):
        val, self.commit_func = self.data['e']()
        return [val]

    def compute_result(self, x):
        return x | (1 << 7)


class Instruction_HALT(SupervisorInstruction):
    bin_format = '0100101011001000'
    name = 'halt'

    # FIXME: What am I supposed to do here? Jump to self?

    def compute_result(self):
        self.jump(None, self.constant(self.addr, LONG_TYPE), JumpKind.Exit)


class Instruction_PULSE(IntegerInstruction):
    bin_format = '0100101011001100'
    name = 'pulse'

    # We don't implement PST. It changes multiple times during xexcution of an
    # instruction


class Instruction_ILLEGAL(IntegerInstruction):
    bin_format = '0100101011111100'
    name = 'illegal'

    def compute_result(self):
        self.trap(4)


class Instruction_MULU_L(MUL_DIV_REM_L, Logic_MULU):
    bin_format = '0100110000eeeeee0ddd000000000000'
    name = 'mulu.l'


# FIXME: the results are always equal to the unsigned version. There must be a
# resaon to have two opcodes, no?
class Instruction_MULS_L(MUL_DIV_REM_L, Logic_MULS):
    bin_format = '0100110000eeeeee0ddd100000000000'
    name = 'muls.l'


class Instruction_DIVU_L(DIV_L, Op_DIVU):
    bin_format = '0100110001eeeeee0ddd000000000www'
    name = 'divu.l'


class Instruction_REMU_L(REM_L, Op_DIVU):
    bin_format = '0100110001eeeeee0ddd000000000www'
    name = 'remu.l'


class Instruction_DIVS_L(DIV_L, Op_DIVS):
    bin_format = '0100110001eeeeee0ddd100000000www'
    name = 'divs.l'


class Instruction_REMS_L(REM_L, Op_DIVS):
    bin_format = '0100110001eeeeee0ddd100000000www'
    name = 'rems.l'


class Instruction_SATS(Unary, Logic):
    bin_format = '0100110010000ddd'
    name = 'sats'

    def compute_result(self, x):
        y = x.bit(x.width - 1).cast_to(x.ty, signed=True)
        return self.itevv(self.get_overflow(), y ^ (1 << (x.width - 1)), x)


class Instruction_TRAP(IntegerInstruction):
    bin_format = '010011100100IIII'
    name = 'trap'

    def _fetch_operands(self):
        return [int(self.data['I'], 2)]

    def compute_result(self, imm):
        self.trap(32 + imm, self.next_pc())


class Instruction_LINK(IntegerInstruction):
    bin_format = '0100111001010aaa'
    name = 'link'

    def _extra_parsing(self, data, bitstrm):
        data['I'] = self.read_word(bitstrm)
        return super()._extra_parsing(data, bitstrm)

    def _fetch_operands(self):
        areg, self.commit_func = self.fetch_eff(
            self.data['a'], Mode.AREG_DIRECT_MODE, None, LONG_TYPE)
        imm = self.constant(int(self.data['I'], 2), WORD_TYPE)

        return [imm, areg]

    def compute_result(self, imm, areg):
        self.push(areg)
        cur_sp = self.get_sp()
        self.set_sp(cur_sp + imm.cast_to(LONG_TYPE, signed=True))

        return cur_sp


class Instruction_UNLK(IntegerInstruction):
    bin_format = '0100111001011aaa'
    name = 'unlk'

    def _fetch_operands(self):
        areg, self.commit_func = self.fetch_eff(
            self.data['a'], Mode.AREG_DIRECT_MODE, None, LONG_TYPE)

        return [areg]

    def compute_result(self, areg):
        self.set_sp(areg)
        return self.pop(LONG_TYPE)


class Instruction_MOVE_to_USP(SupervisorInstruction):
    bin_format = '0100111001100aaa'
    name = 'move'

    def _fetch_operands(self):
        usp, _ = self.fetch_eff(
            self.data['a'], Mode.AREG_DIRECT_MODE, None, LONG_TYPE)
        self.commit_func = lambda val: self.put(val, 'usp')

        return [usp]

    def compute_result(self, usp):
        return usp


class Instruction_MOVE_from_USP(SupervisorInstruction):
    bin_format = '0100111001101aaa'
    name = 'move'

    def _fetch_operands(self):
        usp = self.get('usp', LONG_TYPE)
        _, self.commit_func = self.fetch_eff(
            self.data['a'], Mode.AREG_DIRECT_MODE, None, LONG_TYPE)

        return [usp]

    def compute_result(self, usp):
        return usp


class Instruction_NOP(IntegerInstruction):
    bin_format = '0100111001110001'
    name = 'nop'


class Instruction_STOP(SupervisorInstruction):
    bin_format = '0100111001110010'
    name = 'stop'

    def _extra_parsing(self, data, bitstrm):
        data['I'] = self.read_word(bitstrm)
        return super()._extra_parsing(data, bitstrm)

    def _fetch_operands(self):
        imm = self.constant(int(self.data['I'], 2), WORD_TYPE)

        return [imm]

    def compute_result(self, imm):
        self.set_sr(imm)

        # and then... sleep?


class Instruction_RTE(SupervisorInstruction):
    bin_format = '0100111001110011'
    name = 'rte'

    def compute_result(self):
        sp = self.get_sp()
        fmt = self.load(sp, BYTE_TYPE) >> 4
        sr = self.load(sp + 2, WORD_TYPE)
        pc = self.load(sp + 4, LONG_TYPE)

        self.set_sp(sp + 4 + fmt.cast_to(LONG_TYPE))
        self.set_sr(sr)
        self.jump(None, pc, JumpKind.Ret)


class Instruction_RTS(IntegerInstruction):
    bin_format = '0100111001110101'
    name = 'rts'

    def compute_result(self):
        addr = self.pop(LONG_TYPE)
        self.jump(None, addr, JumpKind.Ret)


class Instruction_MOVEC(SupervisorInstruction):
    bin_format = '0100111001111011orrrcccccccccccc'
    name = 'movec'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        try:
            data['c'] = {
                0x2: 'cacr',
                0x3: 'asid',
                0x4: 'acr0',
                0x5: 'acr1',
                0x6: 'acr2',
                0x7: 'acr3',
                0x8: 'mmubar',

                0x801: 'vbr',
                0x80F: 'pc',

                0xC00: 'rombar0',
                0xC01: 'rombar1',
                0xC04: 'rambar0',
                0xC05: 'rambar1',
                0xC0C: 'mpcr',
                0xC0D: 'edrambar',
                0xC0E: 'secmbar',
                0xC0F: 'mbar',

                0xD02: 'pcr1u0',
                0xD03: 'pcr1l0',
                0xD04: 'pcr2u0',
                0xD05: 'pcr2l0',
                0xD06: 'pcr3u0',
                0xD07: 'pcr3l0',
                0xD0A: 'pcr1u1',
                0xD0B: 'pcr1l1',
                0xD0C: 'pcr2u1',
                0xD0D: 'pcr2l1',
                0xD0E: 'pcr3u1',
                0xD0F: 'pcr3l1',
            }[int(data['c'], 2)]
        except KeyError:
            raise ParseError

        try:
            self.lookup_register(self.arch, data['c'])
        except ValueError:
            raise ParseError  # TODO: not yet implemented

    def _fetch_operands(self):
        if self.data['o'] == '0':
            x, _ = self.fetch_eff(
                self.data['r'], Mode.DREG_DIRECT_MODE, None, LONG_TYPE)
        elif self.data['o'] == '1':
            x, _ = self.fetch_eff(
                self.data['r'], Mode.AREG_DIRECT_MODE, None, LONG_TYPE)
        else:
            raise AssertionError

        self.commit_func = lambda v: self.put(v, self.data['c'])

        return [x]

    def compute_result(self, x):
        return x


class Instruction_JSR(JumpingEffAddr):
    bin_format = '0100111010eeeeee'
    name = 'jsr'

    def compute_result(self, dst):
        self.push(self.next_pc())
        self.jump(None, dst, jumpkind=JumpKind.Call)


class Instruction_JMP(JumpingEffAddr):
    bin_format = '0100111011eeeeee'
    name = 'jsr'

    def compute_result(self, dst):
        self.jump(None, dst)


class Instruction_ADDQ(QuickInstruction, Arithmetic_ADD):
    bin_format = '0101III010eeeeee'
    name = 'addq'


class Instruction_Scc(ParseCond):
    bin_format = '0101oooo11000ddd'
    name = 'scc'

    def _fetch_operands(self):
        _, self.commit_func = self.fetch_eff(
            self.data['d'], Mode.DREG_DIRECT_MODE, None, BYTE_TYPE)
        return []

    def compute_result(self):
        return self.itevv(self.data['o'][1](),
                          self.constant(0b11111111, BYTE_TYPE),
                          self.constant(0, BYTE_TYPE))


class Instruction_SUBQ(QuickInstruction, Arithmetic_SUB):
    bin_format = '0101III110eeeeee'
    name = 'subq'


class Instruction_TPF(IntegerInstruction):
    bin_format = '0101000111111ooo'
    name = 'tpf'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        try:
            data['o'] = {
                '010': self.read_word,
                '011': self.read_dword,
                '100': lambda _: None,
            }[data['o']]
        except KeyError:
            raise ParseError

    def _extra_parsing(self, data, bitstrm):
        data['o'](bitstrm)
        return super()._extra_parsing(data, bitstrm)


class Instruction_BRA(JumpingDisplacement):
    bin_format = '01100000IIIIIIII'
    name = 'bra'

    def compute_result(self, dst):
        self.jump(None, dst)


class Instruction_BSR(JumpingDisplacement):
    bin_format = '01100001IIIIIIII'
    name = 'bsr'

    def compute_result(self, dst):
        self.push(self.next_pc())
        self.jump(None, dst, jumpkind=JumpKind.Call)


class Instruction_Bcc(JumpingDisplacement, ParseCond):
    bin_format = '0110ooooIIIIIIII'
    name = 'bcc'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        if data['o'][0] in {'0000', '0001'}:
            raise ParseError

    def compute_result(self, dst):
        self.jump(self.data['o'][1](), dst)


class Instruction_MOVEQ(CcFromFirst):
    bin_format = '0111ddd0IIIIIIII'
    name = 'moveq'

    def _fetch_operands(self):
        _, self.commit_func = self.fetch_eff(
            self.data['d'], Mode.DREG_DIRECT_MODE, None, LONG_TYPE)
        imm = self.constant(int(self.data['I'], 2), BYTE_TYPE)

        return [imm]

    def compute_result(self, imm):
        return imm.cast_to(LONG_TYPE, signed=True)


class Instruction_MVS_MVZ(CcFromFirst):
    bin_format = '0111ddd1ooeeeeee'
    name = 'mvs/mvz'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        self.name, data['signed'], data['t'] = {
            '00': ('mvs.b', True, BYTE_TYPE),
            '01': ('mvs.w', True, WORD_TYPE),
            '10': ('mvz.b', False, BYTE_TYPE),
            '11': ('mvz.w', False, WORD_TYPE),
        }[data['o']]

        data['E'], data['e'] = self.parse_eff(bitstrm, data['e'], data['t'])

    def _fetch_operands(self):
        _, self.commit_func = self.fetch_eff(
            self.data['d'], Mode.DREG_DIRECT_MODE, None, LONG_TYPE)
        src, _ = self.data['e']()

        return [src]

    def compute_result(self, imm):
        return imm.cast_to(LONG_TYPE, signed=self.data['signed'])

    def negative(self, *args):
        if not self.data['signed']:
            return self.constant(0, BOOL_TYPE)

        return super().negative(*args)


class Instruction_OR(OpmodeDeterminesDirectionNoAreg, Logic_OR):
    bin_format = '1000dddoooeeeeee'
    name = 'or'


class Instruction_DIVU_W(DIV_W, Op_DIVU):
    bin_format = '1000ddd011eeeeee'
    name = 'divu.w'


class Instruction_DIVS_W(DIV_W, Op_DIVS):
    bin_format = '1000ddd111eeeeee'
    name = 'divs.w'


class Instruction_SUB(OpmodeDeterminesDirection, Arithmetic_SUB):
    bin_format = '1001dddoooeeeeee'
    name = 'sub'


class Instruction_SUBX(Extended, DyDx, Arithmetic_SUB):
    bin_format = '1001ddd110000sss'
    name = 'subx'


class Instruction_SUBA(OverrideNoCc, EayAx, Arithmetic_SUB):
    bin_format = '1001aaa111eeeeee'
    name = 'suba'


class Instruction_MOVE_to_ACC(EMACInstruction):
    bin_format = '10100oo100eeeeee'
    name = 'move'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)
        data['E'], data['e'] = self.parse_eff(bitstrm, data['e'], BYTE_TYPE)

        if not data['E'] in {
            Mode.DREG_DIRECT_MODE,
            Mode.AREG_DIRECT_MODE,
            Mode.IMMEDIATE_DATA,
        }:
            raise ParseError

    def _fetch_operands(self):
        newacc, _ = self.data['e']()
        self.commit_func = lambda value: self.put(
            value, ArchMCF54455.acc_reg(self.data['o']))

        return [newacc]

    def compute_result(self, acc):
        return acc


class Instruction_MOVE_to_EMAC(EMACInstruction):
    bin_format = '10101oo100eeeeee'
    name = 'move'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)
        data['E'], data['e'] = self.parse_eff(bitstrm, data['e'], BYTE_TYPE)

        if not data['E'] in {
            Mode.DREG_DIRECT_MODE,
            Mode.AREG_DIRECT_MODE,
            Mode.IMMEDIATE_DATA,
        }:
            raise ParseError

        try:
            data['o'] = {
                '00': 'macsr',
                '01': 'accext01',
                '10': 'mask',
                '11': 'accext23',
            }[data['o']]
        except KeyError:
            raise ParseError

    def _fetch_operands(self):
        newval, _ = self.data['e']()
        self.commit_func = lambda value: self.put(value, self.data['o'])

        return [newval]

    def compute_result(self, val):
        return val


class Instruction_MOV3Q(CcFromFirst, ParseEff):
    bin_format = '1010III101eeeeee'
    name = 'mov3q'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        if data['E'] in {
            Mode.IMMEDIATE_DATA,
            Mode.PC_INDIRECT_DISPLACEMENT_MODE,
            Mode.PC_INDIRECT_SCALED_INDEX_MODE,
        }:
            raise ParseError

    def _fetch_operands(self):
        _, self.commit_func = self.data['e']()
        if self.data['I'] == '000':
            imm = self.constant(-1, LONG_TYPE)
        else:
            imm = self.constant(int(self.data['I'], 2), LONG_TYPE)

        return [imm]

    def compute_result(self, x):
        return x


class Instruction_CMP(Arithmetic_SUB):
    bin_format = '1011rrroooeeeeee'
    name = 'cmp'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        try:
            self.name, data['areg'], data['t'] = {
                '000': ('cmp.b', False, BYTE_TYPE),
                '001': ('cmp.w', False, WORD_TYPE),
                '010': ('cmp.l', False, LONG_TYPE),
                '011': ('cmpa.w', True, WORD_TYPE),
                '111': ('cmpa.l', True, LONG_TYPE),
            }[data['o']]
        except KeyError:
            raise ParseError

        data['E'], data['e'] = self.parse_eff(bitstrm, data['e'], data['t'])

    def _fetch_operands(self):
        src, _ = self.data['e']()
        if self.data['areg']:
            reg, _ = self.fetch_eff(
                self.data['r'], Mode.AREG_DIRECT_MODE, None, LONG_TYPE)
            src = src.cast_to(LONG_TYPE)
        else:
            reg, _ = self.fetch_eff(
                self.data['r'], Mode.DREG_DIRECT_MODE, None, self.data['t'])

        return [reg, src]

    def extend(self, *args):
        return None


class Instruction_EOR(DyEax, Logic_EOR):
    bin_format = '1011ddd110eeeeee'
    name = 'eor'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        if data['E'] in {
            Mode.AREG_DIRECT_MODE,
            Mode.IMMEDIATE_DATA,
            Mode.PC_INDIRECT_DISPLACEMENT_MODE,
            Mode.PC_INDIRECT_SCALED_INDEX_MODE,
        }:
            raise ParseError


class Instruction_AND(OpmodeDeterminesDirectionNoAreg, Logic_AND):
    bin_format = '1100dddoooeeeeee'
    name = 'and'


class Instruction_MULU_W(MUL_W, Logic_MULU):
    bin_format = '1100ddd011eeeeee'
    name = 'mulu.w'


class Instruction_MULS_W(MUL_W, Logic_MULS):
    bin_format = '1100ddd111eeeeee'
    name = 'muls.w'


class Instruction_ADD(OpmodeDeterminesDirection, Arithmetic_ADD):
    bin_format = '1101dddoooeeeeee'
    name = 'add'


class Instruction_ADDX(Extended, DyDx, Arithmetic_ADD):
    bin_format = '1101ddd110000sss'
    name = 'addx'


class Instruction_ADDA(OverrideNoCc, EayAx, Arithmetic_ADD):
    bin_format = '1101aaa111eeeeee'
    name = 'adda'


class Instruction_Shift(Logic):
    bin_format = '1110ccco10t0oddd'
    name = 'asl/asr/lsl/lsr'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        self.name, data['left'], data['logic'] = {
            '00': ('asr', False, False),
            '01': ('lsr', False, True),
            '10': ('asl', True, False),
            '11': ('lsl', True, True),
        }[data['o']]

    def _fetch_operands(self):
        dreg, self.commit_func = self.fetch_eff(
            self.data['d'], Mode.DREG_DIRECT_MODE, None, LONG_TYPE)

        if self.data['t'] == '0':
            if self.data['c'] == '000':
                count = self.constant(8, BYTE_TYPE)
            else:
                count = self.constant(int(self.data['c'], 2), BYTE_TYPE)
        elif self.data['t'] == '1':
            count, _ = self.fetch_eff(
                self.data['c'], Mode.DREG_DIRECT_MODE, None, BYTE_TYPE)
            count %= 64
        else:
            raise AssertionError

        return [dreg, count]

    def compute_result(self, x, count):
        if self.data['left']:
            return x << count
        with signedness([x], not self.data['logic']):
            if not self.data['left'] and not self.data['logic']:
                return self.itevv(
                    count >= 32, self.constant(0xFFFFFFFF, LONG_TYPE),
                    x >> count)
            return x >> count

    def carry(self, x, count, retval):
        # bound count to 1-32
        count_cp = count
        count_cp = self.itevv(count_cp <= 32, count_cp,
                              self.constant(32, BYTE_TYPE))
        count_cp = self.itevv(count_cp >= 1, count_cp,
                              self.constant(1, BYTE_TYPE))

        bitnum = count_cp - 1
        if self.data['left']:
            bitnum = 31 - bitnum

        res = x.bit(bitnum)

        fill = self.constant(0, BOOL_TYPE)
        if not self.data['left'] and not self.data['logic']:
            fill = self.constant(1, BOOL_TYPE)

        res = self.itevv(count <= 32, res, fill)
        res = self.itevv(count >= 1, res, self.constant(0, BOOL_TYPE))

        return res

    def extend(self, x, count, retval):
        # return self.carry(x, count, retval)
        return self.itevv(count == 0, self.get_extend(),
                          self.carry(x, count, retval))


class Instruction_INTOUCH(SupervisorInstruction):
    bin_format = '1111010000101aaa'
    name = 'intouch'

    def _fetch_operands(self):
        areg, _ = self.fetch_eff(
            self.data['a'], Mode.AREG_DIRECT_MODE, None, LONG_TYPE)
        return [areg]

    def compute_result(self, x):
        pass


class Instruction_CPUSHL(SupervisorInstruction):
    bin_format = '11110100cc101aaa'
    name = 'cpushl'

    def _fetch_operands(self):
        areg, _ = self.fetch_eff(
            self.data['a'], Mode.AREG_DIRECT_MODE, None, LONG_TYPE)
        return [areg]

    def compute_result(self, x):
        pass


class Instruction_WDDATA(IntegerInstruction):
    bin_format = '11111011ooeeeeee'
    name = 'wddata'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        try:
            self.name, data['t'] = {
                '00': ('wddata.b', BYTE_TYPE),
                '01': ('wddata.w', WORD_TYPE),
                '10': ('wddata.l', LONG_TYPE),
            }[data['o']]
        except KeyError:
            raise ParseError

        data['E'], data['e'] = self.parse_eff(bitstrm, data['e'], data['t'])

        if data['E'] in {
            Mode.DREG_DIRECT_MODE,
            Mode.AREG_DIRECT_MODE,
            Mode.IMMEDIATE_DATA,
            Mode.PC_INDIRECT_DISPLACEMENT_MODE,
            Mode.PC_INDIRECT_SCALED_INDEX_MODE,
        }:
            raise ParseError

    def _fetch_operands(self):
        x, _ = self.data['e']()
        return [x]

    def compute_result(self, x):
        pass


class Instruction_WDEBUG(SupervisorInstruction, LoadEffectiveAddress):
    bin_format = '1111101111eeeeee0000000000000011'
    name = 'wdebug'

    def match_instruction(self, data, bitstrm):
        super().match_instruction(data, bitstrm)

        if data['E'] not in {
            Mode.AREG_INDIRECT_MODE,
            Mode.AREG_INDIRECT_DISPLACEMENT_MODE,
            Mode.IMMEDIATE_DATA,
        }:
            raise ParseError

    def _fetch_operands(self):
        x, _ = self.data['e']()
        return [x]
