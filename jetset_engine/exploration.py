import subprocess
import time
from qmp import AvoidPointError, HitPointError
from collections import defaultdict
from analysis.debug import *
import os
from socket import timeout
import sys

class ExplorationManager(object):
    """docstring for ExplorationManager"""
    def __init__(self, vm_constructor, args, cmd):
        self.vm_constructor = vm_constructor
        self.vm_args = args
        self.cmd = cmd
        self.aggregated_decisions = defaultdict(set)
        self.decision_cache = {} # loc_key = decision
        self.start_time = time.time()
        logger.clear_explorer_log()


    # return loc_key,decision
    def choose_backtrack_point(self, vm):
        min_score = 1000000000 
        best = () 
        for loc_key, decision, forced in reversed(vm.decision_log): 
            if not forced and loc_key not in self.decision_cache: 
                pc,callstack = loc_key 
                score = vm.strat.metric.get_score(pc,callstack) 
                if score < min_score: 
                    min_score = score 
                    not_decision = (1 if decision == 0 else 0)
                    best = (loc_key, not_decision) 
        return best


    def run_one(self, decision_cache):
        try:
            proc = subprocess.Popen(self.cmd)
            time.sleep(2)
            vm = self.vm_constructor(self.vm_args, decision_cache)
            print("preparing to connect")
            vm.connect()
        except timeout:
            #try exactly 1 once more to connect to VM
            print("Timeout: Trying 1 more time")
            # this for sure kills the process
            os.system(f"pkill -9 qemu-system-arm")
            time.sleep(5)
            proc = subprocess.Popen(self.cmd)
            time.sleep(2)
            vm = self.vm_constructor(self.vm_args, decision_cache)
            vm.connect()
            
        vm.setup()
        vm.start_time = self.start_time
        vm.pre_analysis()
        vm.send_options(vm.arch_num)
        try:
            vm.run()
        except AvoidPointError:
            print("Got AvoidPointError")
        except HitPointError:
            print("Got HitPointError")
        os.system(f"pkill -9 -P {proc.pid}")
        vm.post_analysis()
        logger.update_log()
        return vm

    def run(self):
        # curr_decision_log
        for idx in range(10):
            time.sleep(3)
            vm = self.run_one(decision_cache=self.decision_cache)
            decision_log = vm.decision_log
            for loc_key,decision,forced in decision_log:
                if not forced:
                    self.aggregated_decisions[loc_key].add(decision)
            cache_loc_key,cache_decision = self.choose_backtrack_point(vm)
            logger.explorer_log("======= Aggregated_decisions: " + str(idx) + "============")
            for k, decisions in self.aggregated_decisions.items():
                pc0,callstack0 = k  
                logger.explorer_log(loc_key_str(k) + str(decisions) + str(vm.strat.metric.get_score(pc0, callstack0)))
            logger.explorer_log("============= Chosen ==============")
            logger.explorer_log("Backtracking to: " + loc_key_str(cache_loc_key) + " = " + str(cache_decision))
            logger.explorer_log("===========================")
            assert(cache_loc_key not in self.decision_cache)
            self.decision_cache[cache_loc_key] = cache_decision
            logger.explorer_log(str(self.decision_cache))

