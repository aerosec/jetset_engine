import argparse

REALLY_BIG_NUMBER = 100000

class JetSetVar(object):
    """docstring for JetSetVar"""
    def __init__(self, v, taint, is_symbolic):
        self.v = v 
        self.taint = taint
        self.is_symbolic = is_symbolic

    def __str__(self):
        return (f"s{self.v}({hex(self.taint)})" if self.is_symbolic else hex(self.v))

    def __repr__(self):
        return (f"s{self.v}({hex(self.taint)})" if self.is_symbolic else hex(self.v)) 
        

def parse_dst(data):
    v = data['dst']
    v_taint = data['dst_taint']
    v_is_symbolic = v_taint != 0
    return JetSetVar(v,v_taint,v_is_symbolic)

def parse_arg(data, n):
    v = data[f'arg{n}']
    v_taint = data[f'arg{n}_is_symbolic']
    v_is_symbolic = v_taint != 0
    return JetSetVar(v,v_taint,v_is_symbolic)

def resolve_function(addr, beagle=False):
    if not beagle:
        return hex(addr)

    with open('strats/mlo_system.map') as fd:
        lines = [l.split() for l in fd.readlines()]
    for i in range(len(lines) - 1):
        if int(lines[i][0], 16) <= addr and int(lines[i + 1][0], 16) > addr:
            return str([lines[i][-1], hex(addr)])

    return str([lines[i + 1][-1], hex(addr)])

def get_args():
    parser = argparse.ArgumentParser(description='Run Symbolic Execution engine for Jetset')
    parser.add_argument('--useFunctionPrologues', 
        dest='use_function_prologues', 
        default=False, 
        action='store_true',
        help="Try to infer the start of functions (for CFG) using architecture specific function prologues")
    parser.add_argument('--useSlicer', 
        dest='use_slicer', 
        default=False, 
        action='store_true',
        help="Use constraint slicer to improve performance of constraint solving")
    parser.add_argument('--useFinalizer', 
        dest='use_finalized_decisions', 
        default=False, 
        action='store_true',
        help="After making a certain decision n times, finalize and make that always the solution")
    parser.add_argument('--verbose', 
        dest='verbose', 
        default=False, 
        action='store_true',
        help="Print out all log messages and other warnings")
    parser.add_argument('--noAutoDetectLoops', 
        dest='auto_detect_loops', 
        default=True, 
        action='store_false',
        help="Omit auto loop detection")
    parser.add_argument('--port', 
        dest='port', 
        default=4444, 
        type=int,
        help='Port number to communicate with Qemu (over localhost)')
    parser.add_argument('--soc', 
        dest='socname', 
        help='Type of soc (console | heat_press | steering_control | robot | gateway | drone | reflow_oven | cnc | stm32f4 | rpi | beagle)')

    parser.add_argument('-o', 
        dest='outfile', 
        default="out.device.c",
        help='output file')

    parser.add_argument('--cmdfile', 
        dest='cmdfile',
        default=None, 
        help="path to script to invoke qemu instance. If window doesn't open, make sure that the qemu run script is executable")

    args = parser.parse_args()
    return args
    
