from analysis.base.metric import L1Metric
from fastresolver import FastResolver
from angr.analyses.cfg.cfg_fast import CFGJob
from analysis.debug import *

# Logging to show how the cfg has changed (no effect on state)
def diff_cfgs(func_blocks, post_blocks):
    for faddr in func_blocks:
        if faddr not in post_blocks:
            print("func: ", hex(faddr), "removed")
    for faddr in post_blocks:
        if faddr not in func_blocks:
            print("func: ", hex(faddr), "added")

    for faddr,func in post_blocks.items():
        if faddr in func_blocks:
            func2 = func_blocks[faddr]
            new_blocks = set(func) - set(func2)
            if new_blocks:
                print("Blocks added to function", hex(faddr), new_blocks)
            removed_blocks = set(func2) - set(func)
            if removed_blocks:
                print("Blocks removed from function", hex(faddr), removed_blocks)

def run_job(cfg, addr, job):
    # incrementally add to the cfg
    func_blocks = {}
    for faddr,func in cfg.functions.items():
        func_blocks[faddr] = list(func.blocks)
    cfg._insert_job(job)
    cfg._register_analysis_job(addr, job)
    cfg._analysis_core_baremetal()
    cfg._post_analysis(incremental=True)
    # Logging stuff
    post_blocks = {}
    for faddr,func in cfg.functions.items():
        post_blocks[faddr] = list(func.blocks)

def run_boring_job(cfg, addr, faddr):
    job = CFGJob(addr, faddr, 'Ijk_Boring')
    run_job(cfg, addr, job)

class DynL1Metric(L1Metric):
    def __init__(self, vm, p, find, avoid=[], extra_options={}, discovered_edges=[],
                 extra_starts=[]):
        self.vm = vm
        self.p = p
        self.extra_options = extra_options
        self.starts = [p.entry]
        self.starts.extend(extra_starts)
        self.discovered_edges = discovered_edges
        self.avoid = avoid
        self.cfg = None  # avoid attribute error
        self.cfg = self.mk_cfg()
        super(DynL1Metric, self).__init__(find=find, cfg=self.cfg)

    def mk_block_index(self, cfg):
        ''' generate mapping from insn addr to block addr'''
        index = {}
        for block in cfg.nodes():
            if block.block:
                for insn_addr in block.block.instruction_addrs:
                    index[insn_addr] = block.addr
        return index

    def mk_cfg(self):
        if 'function_prologues' in self.extra_options:
            function_prologues = self.extra_options['function_prologues']
        else:
            function_prologues = True

        if 'resolve_indirect_jumps' in self.extra_options:
            should_resolve_ij = self.extra_options['resolve_indirect_jumps']
        else:
            should_resolve_ij = False    
        # Generate CFG
        # assumes that self.starts has been updated
        cfg = self.p.analyses.CFGFast(function_starts=self.starts,
                                      force_complete_scan=False,
                                      normalize=True,
                                      indirect_jump_resolvers=[FastResolver(self.p)],
                                      resolve_indirect_jumps=should_resolve_ij,
                                      function_prologues=function_prologues)

        self.block_index = self.mk_block_index(cfg)
        print("cfg has been made with nodes = ", len(cfg.graph.nodes()),
              " and edges = ", len(cfg.graph.edges()))
        return cfg

    def update_cfg(self, addr, callstack):
        logger.log("update_cfg @ " + hex(addr))
        for ret_addr in callstack:
            if (ret_addr != 0) and ret_addr not in self.block_index:
                run_boring_job(self.cfg, ret_addr, ret_addr)
        self.block_index = self.mk_block_index(self.cfg)
        # update block_index
        if addr not in self.block_index:
            run_boring_job(self.cfg, addr, addr)
            self.block_index = self.mk_block_index(self.cfg)
        self.update_distance_structures(self.cfg)
        self.vm.add_loops()

        

    def get_score(self, addr, callstack, visit=False):
        if addr not in self.block_index:
            self.update_cfg(addr, callstack)
            self.target_block = self.cfg.get_node(self.find_point)

        return super(DynL1Metric, self).get_score(addr, callstack)
