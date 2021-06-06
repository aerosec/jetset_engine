from enum import Enum

from archinfo.arch import register_arch, Arch, Register, Endness
from archinfo.tls import TLSArchInfo

try:
    import capstone as _capstone
except ImportError:
    _capstone = None

try:
    import unicorn as _unicorn
except ImportError:
    _unicorn = None


class ArchMCF54455(Arch):
    def __init__(self, endness=Endness.BE):
        # Force BE
        super().__init__(Endness.BE)
        self.uc_mode = _unicorn.UC_MODE_BIG_ENDIAN

    name = 'MCF54455'
    bits = 32
    vex_arch = None
    qemu_name = 'm68k'
    ida_processor = None
    triplet = None

    max_inst_bytes = 6

    vex_conditional_helpers = None
    call_pushes_ret = True

    # function_prologs = [
    #     br'\x4e\x56',  # link a6,#?
    # ]
    # function_epilogs = [
    #     br'\x4e\x5e',  # unlk a6
    # ]
    ret_instruction = b'\x4e\x75'
    nop_instruction = b'\x4e\x71'
    instruction_alignment = 2

    if _capstone:
        cs_arch = _capstone.CS_ARCH_M68K
        cs_mode = _capstone.CS_MODE_BIG_ENDIAN
    if _unicorn:
        uc_arch = _unicorn.UC_ARCH_M68K
        uc_mode = _unicorn.UC_MODE_BIG_ENDIAN
        uc_const = _unicorn.m68k_const
        uc_prefix = "UC_M68K_"

    elf_tls = TLSArchInfo(1, 56, [8], [4], [0], 0, 0)
    sizeof = {'short': 16, 'int': 32, 'long': 32, 'long long': 64}

    register_list = [
        Register(name='d0', size=4, general_purpose=True, argument=True,
                 subregisters=[('d0.w', 2, 2), ('d0.b', 3, 1)]),
        Register(name='d1', size=4, general_purpose=True, argument=True,
                 subregisters=[('d1.w', 2, 2), ('d1.b', 3, 1)]),
        Register(name='d2', size=4, general_purpose=True, argument=True,
                 subregisters=[('d2.w', 2, 2), ('d2.b', 3, 1)]),
        Register(name='d3', size=4, general_purpose=True, argument=True,
                 subregisters=[('d3.w', 2, 2), ('d3.b', 3, 1)]),
        Register(name='d4', size=4, general_purpose=True, argument=True,
                 subregisters=[('d4.w', 2, 2), ('d4.b', 3, 1)]),
        Register(name='d5', size=4, general_purpose=True, argument=True,
                 subregisters=[('d5.w', 2, 2), ('d5.b', 3, 1)]),
        Register(name='d6', size=4, general_purpose=True, argument=True,
                 subregisters=[('d6.w', 2, 2), ('d6.b', 3, 1)]),
        Register(name='d7', size=4, general_purpose=True, argument=True,
                 subregisters=[('d7.w', 2, 2), ('d7.b', 3, 1)]),
        Register(name='a0', size=4, general_purpose=True, argument=True),
        Register(name='a1', size=4, general_purpose=True, argument=True),
        Register(name='a2', size=4, general_purpose=True, argument=True),
        Register(name='a3', size=4, general_purpose=True, argument=True),
        Register(name='a4', size=4, general_purpose=True, argument=True),
        Register(name='a5', size=4, general_purpose=True, argument=True),
        Register(name='a6', size=4, general_purpose=True, argument=True,
                 alias_names=('bp',),),
        # a7 swaps with other_a7 when SR change
        Register(name='a7', size=4, general_purpose=True,
                 alias_names=('sp',),),
        # address this as other_a7 when swapping, usp when explicit access
        Register(name='other_a7', size=4, general_purpose=True,
                 alias_names=('usp',),),
        Register(name='vbr', size=4),
        Register(name='cacr', size=4),
        Register(name='asid', size=4),
        Register(name='acr0', size=4),
        Register(name='acr1', size=4),
        Register(name='acr2', size=4),
        Register(name='acr3', size=4),
        Register(name='mmubar', size=4),
        Register(name='rombar0', size=4),
        Register(name='rombar1', size=4),
        Register(name='rambar0', size=4),
        Register(name='rambar1', size=4),
        Register(name='mbar', size=4),
        Register(name='macsr', size=4),
        Register(name='acc0', size=4),
        Register(name='acc1', size=4),
        Register(name='acc2', size=4),
        Register(name='acc3', size=4),
        Register(name='accext01', size=4),
        Register(name='accext23', size=4),
        Register(name='mask', size=4),
        Register(name='pc', size=4, alias_names=('ip',),),
        Register(name='sr', size=2, subregisters=[('ccr', 1, 1)]),
        Register(name='ip_at_syscall', size=4),
        Register(name='trap_num', size=4),
    ]

    # This is not numbered the same as the effective address mode
    class Mode(Enum):
        DREG_DIRECT_MODE = 0
        AREG_DIRECT_MODE = 1
        AREG_INDIRECT_MODE = 2
        AREG_INDIRECT_POSTINCREMENT_MODE = 3
        AREG_INDIRECT_PREDECREMENT_MODE = 4
        AREG_INDIRECT_DISPLACEMENT_MODE = 5
        AREG_INDIRECT_SCALED_INDEX_MODE = 6
        PC_INDIRECT_DISPLACEMENT_MODE = 7
        PC_INDIRECT_SCALED_INDEX_MODE = 8
        ABSOLUTE_SHORT_ADDRESSING_MODE = 9
        ABSOLUTE_LONG_ADDRESSING_MODE = 10
        IMMEDIATE_DATA = 11

    def data_reg(bits):
        try:
            bits = int(bits, 2)
        except TypeError:
            pass

        return 'd' + str(bits)

    def address_reg(bits):
        try:
            bits = int(bits, 2)
        except TypeError:
            pass

        if bits == 7:
            return 'sp'
        return 'a' + str(bits)

    def acc_reg(bits):
        try:
            bits = int(bits, 2)
        except TypeError:
            pass

        return 'acc' + str(bits)


vex_offset = 0
for register in ArchMCF54455.register_list:
    register.vex_offset = vex_offset
    vex_offset += register.size


register_arch([r'(mcf|MCF)(?:54455)?'], 32, 'Iend_LE', ArchMCF54455)
