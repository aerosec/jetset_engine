from qmp import RemoteQemuVm
from analysis.base.dynmetric import DynL1Metric
from analysis.base.strats.heapastar import Astar
from tcg_ops import *
from debug import get_args
import configs.socs as socs
from exploration import ExplorationManager
import logging
import os
angr_logger = logging.getLogger('angr')
angr_logger.setLevel(logging.CRITICAL)

class JetSetServer(RemoteQemuVm):
    """docstring for JetSetServer"""
    def __init__(self, args, decision_cache):
        self.args = args
        self.port = args.port
        self.outfile = args.outfile
        super(JetSetServer, self).__init__(decision_cache)
        self.angr_project = socs.get_project(args.socname) 
        self.target = socs.get_target(args.socname) 
        self.avoid = socs.get_avoid(args.socname) 
        self.arch = socs.get_arch(args.socname)
        self.arch_num = socs.get_arch_num(args.socname)
        self.auto_detect_loops = args.auto_detect_loops

    def pre_analysis(self):
        self.device.rpi = (self.args.socname == "rpi")
        self.device.load_config(socs.get_regions(self.args.socname))
        options = {'function_prologues' : self.args.use_function_prologues}
        metric = DynL1Metric(self, self.angr_project, self.target, extra_options=options)
        self.strat = Astar(metric)
        if not self.args.use_finalized_decisions:
            delattr(self.strat,"finalized_decisions")
        print("Booting: ", self.args.socname)
        self.add_bp(self.target, BP_TARGET_FOUND)
        if self.args.socname == "drone":
            self.add_bp(0x08004491, BP_AVOID)
        if self.args.use_slicer:
            self.device.use_slicer = True
        for a in self.avoid:
            self.add_bp(a, BP_AVOID)
        print("Setup Complete!")

    def post_analysis(self):
        print("Post Analysis Complete!")
        
    def decide(self, pc):
        callstack = self.get_callstack(10)
        decision = self.strat.decide(pc, callstack)
        return decision

def main():
    args = get_args()
    cmd = ["xterm", "-e", f"{args.cmdfile}", f"{args.port}"]
    exploration_manager = ExplorationManager(JetSetServer, args, cmd)
    exploration_manager.run()
    print("Done")

if __name__== "__main__":
    main()
