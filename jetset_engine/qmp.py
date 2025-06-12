import sys
import json
import claripy
from qmp_channel import QmpChannel
from tcg_ops import *
from device.remote_device import SymbolicDevice
from analysis.debug import *
import time
from debug import parse_dst, parse_arg
from scripts.eval import base_stats, constraint_stats

NO_FORK = 0
FORK = 1

class AvoidPointError(Exception):
    pass

class HitPointError(Exception):
    pass

class RemoteQemuVm(object):
    """docstring for ClassName"""
    def __init__(self, decision_cache):
        self.qmp_chan = QmpChannel(self.port)
        self.device = SymbolicDevice(use_slicer=True)
        self.watchdog = 0.0
        self.console_output = bytearray()
        self.decision_log = []
        self.decision_cache = decision_cache

    def connect(self):
        self.qmp_chan.connect()

    def setup(self):
        print("VM setup called!")

    def qom_list(self, path):
        cmd = {"execute": "qom-list", "arguments": { "path": path }}
        response = self.qmp_chan.send_cmd(cmd)
        return response['return']

    def qom_get(self, path, property_name):
        cmd = {"execute": "qom-get", "arguments": {"path": path, "property": property_name}}
        response = self.qmp_chan.send_cmd(cmd)
        return response['return']

    def list_commands(self):
        cmd = { "execute": "query-commands" }
        response = self.qmp_chan.send_cmd(cmd)
        for command in response["return"]:
            print(command["name"])

    def is_stopped(self):
        cmd = { "execute": "query-status" }
        response = self.qmp_chan.send_cmd(cmd)
        return not response['return']['running']

    def reset(self):
        cmd = { "execute": "system_reset" }
        self.qmp_chan.send_cmd(cmd)


    def set_irq(self, irqnum, level):
        cmd = { "execute": "set_irq", "arguments" : {"num" : irqnum, "level" : level} }
        result = self.qmp_chan.send_cmd(cmd)
        if result["return"]["queued"] == 1:
            return True
        else:
            return False

    def get_loops(self):
        loops = []
        cfg = self.strat.metric.cfg
        for func in cfg.functions.values(): 
            for block in func.graph: 
                succ = block.successors() 
                if len(succ) == 1 and succ[0] == block and block not in func.ret_sites:
                    node = cfg.get_node(block.addr) 
                    if len(node.successors) == 1 and node.successors[0].addr == block.addr:
                        if node.block.vex.jumpkind != "Ijk_Call":
                            loops.append(block.addr)
        return loops

    def add_loops(self):
        if self.auto_detect_loops:
            for loop in self.get_loops():
                if loop not in self.avoid:
                    self.add_bp(loop, BP_AVOID)
                    self.avoid.append(loop)

    def finalize_decision(self, pc, val):
        cmd = { "execute": "finalize_decision", "arguments" : {"pc" : pc, "val" : val} }
        self.qmp_chan.send_cmd(cmd)

    def finalize_io(self, addr, val):
        cmd = { "execute": "finalize_io", "arguments" : {"addr" : addr, "val" : val} }
        self.qmp_chan.send_cmd(cmd)

    def get_callstack(self, num_frames):
        cmd = { "execute": "get_callstack", "arguments" : {"num_frames" : num_frames} }
        return [frame['ret_addr'] for frame in self.qmp_chan.send_cmd(cmd)['return']]

    def send_options(self, arch):
        cmd = { "execute": "synth_options", "arguments" : {"arch" : arch} }
        self.qmp_chan.send_cmd(cmd)

    def get_pc(self):
        cmd = { "execute": "get_eip" }
        result =  self.qmp_chan.send_cmd(cmd)
        return result['return']['addr']

    def add_bp(self, addr, ty):
        cmd = { "execute": "sc_add_breakpoint", "arguments" : {"addr" : addr, "type" : ty} }
        result =  self.qmp_chan.send_cmd(cmd)

    def do_decision(self, addr, should_fork=NO_FORK):
        cmd = { "execute": "do_decision", "arguments" : {"addr" : addr, "fork" : should_fork } }
        self.qmp_chan.send_cmd(cmd)

    def cont(self):
        cmd = { "execute": "cont" }
        response = self.qmp_chan.send_cmd(cmd)
        if response['return'] != {}:
            print(response)
            assert(False)
        return

    def stop(self):
        cmd = { "execute": "stop" }
        response = self.qmp_chan.send_cmd(cmd)
        return response

    def handle_shutdown(self, data):
        raise (AvoidPointError())


    def decide(self):
        # This should be implemented in subclass
        raise NotImplementedError

    def handle_decision(self, data):
        t0 = time.time()
        pc = data['pc']
        arg1,arg2,condition = data['arg1'],data['arg2'],data['condition']
        arg1_is_symbolic = data['arg1_is_symbolic'] != 0
        arg2_is_symbolic = data['arg2_is_symbolic'] != 0
        cond_str = cond_strs[condition]
        arg1_str = ('s' + str(arg1)) if arg1_is_symbolic else hex(arg1)
        arg2_str = ('s' + str(arg2)) if arg2_is_symbolic else hex(arg2)
        logger.trace_log(
            f"{hex(pc)}: decision: {arg1_str} {cond_str} {arg2_str}")

        callstack = self.get_callstack(10)
        loc_key = (pc, tuple(callstack))
        if hasattr(self.strat, 'finalized_decisions') and loc_key in self.strat.finalized_decisions:
            logger.log(
                f"Hit finalized decision = {self.strat.finalized_decisions[loc_key]} @ {loc_key}"
            )
            decision = self.strat.finalized_decisions[loc_key]
            addr, v = self.device.finalize_mmio_read(condition, arg1,
                                                     arg1_is_symbolic, arg2,
                                                     arg2_is_symbolic,
                                                     decision)
            logger.log(f"finalized io = mmio({hex(addr)}) = {hex(v)}")
            self.finalize_io(addr, v)
            forced = True

        else:
            arg1_symbol = self.device.arg_to_symbol(arg1, arg1_is_symbolic)
            arg2_symbol = self.device.arg_to_symbol(arg2, arg2_is_symbolic)
            self.device.slicer.add_decision_deps(arg1_symbol, arg2_symbol)
            zero_sat, one_sat = self.device.sat_choices(
                arg1_symbol, arg2_symbol, condition)
            if zero_sat and one_sat:
                if loc_key in self.decision_cache:
                    decision = self.decision_cache[loc_key]
                else:
                    decision = self.decide(pc)

                forced = False
                logger.log(
                    hex(pc) + " : " + str([hex(addr) for addr in callstack]) +
                    " decision = " + str(decision))
            elif zero_sat:
                decision = 0
                logger.log(
                    hex(pc) + " : " + str([hex(addr) for addr in callstack]) +
                    " = 0 (forced)")
                forced = True
            else:
                decision = 1
                logger.log(
                    hex(pc) + " : " + str([hex(addr) for addr in callstack]) +
                    " = 1 (forced)")
                forced = True

            self.device.add_decision_constraint(arg1_symbol, arg2_symbol,
                                                condition, decision)

        self.decision_log.append((loc_key, decision, forced))
        self.do_decision(decision)
        t1 = time.time()
        logger.trace_log(f"Decision Time : {t1 - t0}s")
        

    def handle_mmio_read(self, data):
        addr,symbol,size = data['addr'],data['symbol'],data['size']
        logger.trace_log(f"MMIO_READ {hex(data['pc'])}: s{symbol} = mmio_read{size*8}({hex(addr)})")
        self.device.add_mmio_read(addr, symbol, size)

    def handle_mmio_write(self, data):
        addr,val,pc = data['addr'],data['val'],data['pc']
        logger.trace_log(f"MMIO_WRITE {hex(data['pc'])}: mmio_write({hex(addr)}) = {hex(val)}")
        self.device.add_mmio_write(addr, val)
        self.console_output.append(val % 256)

    def handle_ioport_read(self, data):
        portno,symbol = data['portno'],data['symbol']
        logger.trace_log(f"IOPORT_READ {hex(data['pc'])}: s{symbol} = ioport_read({hex(portno)})")
        self.device.add_ioport_read(portno, symbol)

    def handle_ioport_write(self, data):
        portno,val = data['portno'],data['val']
        self.device.add_ioport_write(portno, val)
        self.console_output.append(val % 256)

    def handle_symbolic_binop(self, data):
        dst = parse_dst(data)
        arg1 = parse_arg(data, 1)
        arg2 = parse_arg(data, 2)
        opc = data['opc']
        opc_str = opc_strs[opc]

        logger.trace_log(f"BINOP {hex(data['pc'])}: {str(dst)} = {str(arg1)} {opc_str} {str(arg2)}")

        arg1_symbol = self.device.arg_to_symbol(arg1.v, arg1.is_symbolic)
        arg2_symbol = self.device.arg_to_symbol(arg2.v, arg2.is_symbolic)
        self.device.add_binop_constraint(dst.v, opc, arg1_symbol, arg2_symbol)

    def handle_symbolic_unop(self, data):
        dst = parse_dst(data)
        arg1 = parse_arg(data,1)
        opc = data['opc']
        opc_str = opc_strs[opc]

        logger.trace_log(f"UNOP {hex(data['pc'])}: {str(dst)} = {opc_str}{str(arg1)}")

        arg_symbol = self.device.arg_to_symbol(arg1.v, arg1.is_symbolic)
        self.device.add_unop_constraint(dst.v, opc, arg_symbol)

    def handle_symbolic_deposit(self, data):
        dst = parse_dst(data)
        arg1 = parse_arg(data, 1)
        arg2 = parse_arg(data, 2)
        c0 = data['const0']
        c1 = data['const1']

        logger.trace_log(f"{hex(data['pc'])}: {str(dst)} = deposit({str(arg1)},{str(arg2)},{c0},{hex(c1)})")

        arg1_symbol = self.device.arg_to_symbol(arg1.v, arg1.is_symbolic)
        arg2_symbol = self.device.arg_to_symbol(arg2.v, arg2.is_symbolic)
        self.device.add_deposit_constraint(dst.v, arg1_symbol, arg2_symbol, c0, c1)

    def handle_symbolic_setcond(self, data):
        dst = parse_dst(data)
        arg1 = parse_arg(data, 1)
        arg2 = parse_arg(data, 2)
        condition = data['condition']
        cond_str = cond_strs[condition]
        
        logger.trace_log(f"{hex(data['pc'])} {str(dst)} = {str(arg1)} {cond_str} {str(arg2)}")

        arg1_symbol = self.device.arg_to_symbol(arg1.v, arg1.is_symbolic)
        arg2_symbol = self.device.arg_to_symbol(arg2.v, arg2.is_symbolic)
        self.device.add_setcond_constraint(dst.v, arg1_symbol, arg2_symbol, condition)

    def handle_symbolic_ccall(self, data):
        dst,dst_taint = data['dst'],data['dst_is_symbolic']
        dst_is_symbolic = dst_taint != 0
        dst_str = ("s" + str(dst)) if dst_is_symbolic else hex(dst)

        arg0 = parse_arg(data, 0)
        arg1 = parse_arg(data, 1)
        arg2 = parse_arg(data, 2)
        arg3 = parse_arg(data, 3)

        if self.arch == "arm":
            logger.trace_log(f"{hex(data['pc'])}: {dst_str} = arm_ccall({str(arg0)}, {str(arg1)}, {str(arg2)}, {str(arg3)})")

        elif self.arch == "x86":
            dst_str += f"({hex(dst_taint)})"
            logger.trace_log(f"{hex(data['pc'])}: {dst_str} = x86_ccall({str(arg0)}, {str(arg1)}, {str(arg2)}, {str(arg3)})")
            self.device.add_x86_ccall_constraints(dst_is_symbolic,arg0.is_symbolic,arg1.is_symbolic,arg2.is_symbolic,arg3.is_symbolic,dst,arg0.v,arg1.v,arg2.v,arg3.v)


    def handle_bp_triggered(self, data):
        addr,ty = data['addr'],data['type']
        callstack_str = [hex(frame['ret_addr']) for frame in data['callstack']]
        pc = addr
        if ty == BP_TARGET_FOUND:
            logger.log(f"TARGET HIT: {hex(pc)} : {callstack_str}")
            with open(self.outfile, 'w+') as f:
                synthesis_t_start = time.time()
                device_str = self.device.mk_device()
                synthesis_t_end = time.time()
                f.write(device_str)
                base_stats(self.device)
                constraint_stats(self.device)
                print("Execution Time: ", synthesis_t_start - self.start_time)
                print("Synthesis Time: ", synthesis_t_end - synthesis_t_start)
            sys.exit()

        elif ty == BP_AVOID:
            logger.log(f"AVOID POINT HIT: {hex(pc)} : {callstack_str}")
            raise (AvoidPointError())
        else:
            raise ("Invalid Breakpoint Type = " + ty)

    def handle_event(self, event):
        """
        @param event JSON obj parsed from qemu
        """
        logger.log_msg(str(event))
        if event['event'] == 'TAINTED_DECISION':
            self.handle_decision(event['data'])
        elif event['event'] == 'MMIO_READ':
            self.handle_mmio_read(event['data'])
        elif event['event'] == 'MMIO_WRITE':
            self.handle_mmio_write(event['data'])
        elif event['event'] == 'IOPORT_READ':
            self.handle_ioport_read(event['data'])
        elif event['event'] == 'IOPORT_WRITE':
            self.handle_ioport_write(event['data'])
        elif event['event'] == 'SYMBOLIC_BINOP':
            self.handle_symbolic_binop(event['data'])
        elif event['event'] == 'SYMBOLIC_UNOP':
            self.handle_symbolic_unop(event['data'])
        elif event['event'] == 'SYMBOLIC_DEPOSIT':
            self.handle_symbolic_deposit(event['data'])
        elif event['event'] == 'SYMBOLIC_SETCOND':
            self.handle_symbolic_setcond(event['data'])
        elif event['event'] == 'BP_TRIGGERED':
            self.handle_bp_triggered(event['data'])
        elif event['event'] == 'SYMBOLIC_CCALL':
            self.handle_symbolic_ccall(event['data'])
        elif event['event'] == 'SHUTDOWN':
            self.handle_shutdown(event['data'])
        else:
            pass


    def flush_qmp_chan(self):
        while self.qmp_chan.event_queue:
            event = self.qmp_chan.pop_event()
            self.handle_event(event)

    def activate_watchdog(self):
        pc = self.get_pc()
        callstack_str = [hex(ret_addr) for ret_addr in self.get_callstack(10)]
        logger.log_watchdog(f"{hex(pc)} : {callstack_str}")
        intr_queued = self.set_irq(2,1) # dummy values

    def listen(self):
        print("Listening for new Events...")
        while True:
            t = time.time()
            if t > self.watchdog + 1:
                self.activate_watchdog()
                self.watchdog = t

            # Handle all events in the event_queue
            self.flush_qmp_chan()

            # Get byte array of message if socket has sent data
            msg = self.qmp_chan.maybe_get_msg()
            if msg is not None:
                response = json.loads(msg)
                self.handle_event(response)

    def run(self):
        assert(self.is_stopped())
        self.cont()
        self.listen()
