from angr.simos import SimOS, register_simos
from angr.sim_procedure import SimProcedure
from angr.calling_conventions import (
    SimCC, SimStackArg, SimRegArg, register_syscall_cc, register_default_cc)

from .arch_mcf54455 import ArchMCF54455

SUPERVISOR_BIT_IND = 13


class SimCCMCF54455(SimCC):
    ARG_REGS = []
    FP_ARG_REGS = []    # TODO: ???
    STACKARG_SP_DIFF = 4
    RETURN_ADDR = SimStackArg(0, 4)
    RETURN_VAL = SimRegArg('d0', 4)
    ARCH = ArchMCF54455


class DoTrap(SimProcedure):
    def run(self):
        sr = self.state.regs.sr

        supervisor = self.state.solver.simplify(sr[SUPERVISOR_BIT_IND])
        if not supervisor.concrete:
            raise NotImplementedError

        if self.state.solver.is_false(supervisor):
            self.state.regs.a7, self.state.regs.other_a7 = (
                self.state.regs.other_a7, self.state.regs.a7)
        # TODO: interruputs also affect T/M/I
        self.state.regs.sr = sr | (1 << SUPERVISOR_BIT_IND)

        orig_sp = self.state.regs.a7
        new_sp = orig_sp - (orig_sp & 0b11 | 8)
        self.state.regs.a7 = new_sp

        format = orig_sp & 0b11 | 0b0100
        vector = self.state.regs.trap_num

        # TODO: Determine if we need this
        fs = 0
        fs32 = fs & 0b1100
        fs10 = fs & 0b0011

        self.state.mem[new_sp].long = (
            format << 28 |
            fs32 << 26 |
            vector << 18 |
            fs10 << 16 |
            sr.zero_extend(16)
        ).to_claripy()

        self.state.mem[new_sp + 4].long = \
            self.state.regs.ip_at_syscall.to_claripy()

        new_pc = self.state.mem[
            self.state.regs.vbr | vector << 2].long.resolved
        self.jump(new_pc)


class SimMCF54455(SimOS):
    SYSCALL_TABLE = {}

    def syscall(self, state, allow_unsupported=True):
        p = DoTrap()
        p.addr = 0xFFFFFFFF  # No meaning (yet), just to make it run
        return p


class SimMCF54455Syscall(SimCC):
    ARG_REGS = []
    ARCH = ArchMCF54455

    @staticmethod
    def _match(arch, args, sp_delta):
        return False

    @staticmethod
    def syscall_num(state):
        # FIXME: Does the return value even matter?
        return state.regs.trap_num


register_simos('mcf', SimMCF54455)
register_syscall_cc('MCF54455', 'default', SimMCF54455Syscall)
register_default_cc('MCF54455', SimCCMCF54455)
