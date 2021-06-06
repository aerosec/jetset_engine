import angr
import heapq
from analysis.base.dynmetric import DynL1Metric
from analysis.debug import *

class Astar():
    def __init__(self, metric):
        self.metric = metric
        self.decision_history = {}#last decision made at each point, and the count
        self.decision_trace = [] # sequential history of all decisions
        self.finalized_decisions = {}

    # [addr] -> addr, [addrs]
    def split_by_metric(self, addrs, callstack):
        best_idx = -1
        best_score = REALLY_BIG_NUMBER + REALLY_BIG_NUMBER
        for idx,addr in enumerate(addrs):
            score = self.metric.get_score(addr, callstack, visit=False)

            if score < best_score:
                best_score = score
                best_idx = idx

        return addrs[best_idx]

    def maybe_update_cfg(self, pc, callstack):
        for other_pc,_ in self.decision_history:
            if other_pc == pc:
                return
        self.metric.update_cfg(pc,[])

    def fallback_decide(self, pc, callstack):
        loc_key = (pc,tuple(callstack))
        result = self.decision_history.get(loc_key)
        if result == None:
            # never visited this location, default to 0
            return 0
        prev_decision,count,_ = result
        # else, alternate decisions
        if prev_decision == 1 and count > 3:
            return 0
        elif prev_decision == 0 and count > 3:
            return 1
        else:
            return 0
        return 0

    def get_jmp_target(self, pc):
        block = self.metric.p.factory.block(pc)
        exit_stmt = block.vex.exit_statements[0]
        jmp_target = exit_stmt[2].dst.value
        return jmp_target

    def select_decision(self, addrs, pc):
        try:
            jmp_target = self.get_jmp_target(pc)
        except:
            return -1,""

        score1 = self.metric.get_score(addrs[0], callstack=[])
        score2 = self.metric.get_score(addrs[1], callstack=[])
        if score1 < REALLY_BIG_NUMBER and score2 < REALLY_BIG_NUMBER:

            if addrs[0] == jmp_target:
                if score1 < score2:
                    decision = 1
                else:
                    decision = 0
                metric_str = f" : {score2} {score1}"
                return decision,metric_str
            elif addrs[1] == jmp_target:
                if score2 < score1:
                    decision = 0
                else:
                    decision = 1
                metric_str = f" : {score1} {score2}"
                return decision,metric_str
            else:
                assert(False)
        else:
            return -1,""

    def updated_decision_log(self, loc_key, decision):
        result = self.decision_history.get(loc_key)
        if result == None:
            return decision,1,1
        prev_decision,count,total_count = result
        if total_count > 200 and hasattr(self,"finalized_decisions"):
            self.finalized_decisions[loc_key] = decision
        if prev_decision == decision:
            return prev_decision,(count + 1),total_count+1
        else:
            return decision,1,total_count+1


    def maybe_try_something_new(self, curr_decision, pc, callstack):
        loc_key = (pc, tuple(callstack))
        result = self.decision_history.get(loc_key)

        if result == None:
            return curr_decision

        prev_decision, count, _ = result
        # else, alternate decisions
        if prev_decision == 1 and count > 3:
            return 0
        elif prev_decision == 0 and count > 3:
            return 1
        else:
            return 0

    def decide(self, pc, callstack):
        # 1. if necessary, update cfg / distance metrics
        self.maybe_update_cfg(pc, callstack)
        try:
            succ_nodes = self.metric.cfg.get_node(
                self.metric.block_index[pc]).successors
        except:
            decision = self.fallback_decide(pc, callstack)
            logger.log(f"Cannot find current location in CFG: invoking fallback decide = {decision} @ {hex(pc) + ' : ' + str([hex(addr) for addr in callstack])}")
            return decision
       
        addrs = [node.addr for node in succ_nodes]
        decision = -1
        # 2. Select a state
        if self.metric.cfg.get_node(pc) and len(addrs) == 2:
            decision, metric_str = self.select_decision(addrs, pc)
            decision = self.maybe_try_something_new(decision, pc, callstack)

        # if we can't find a path on the cfg to target, use fallback strat
        if decision == -1:
            decision = self.fallback_decide(pc, callstack)
            metric_str = ""
        # 3. log this decision
        loc_key = (pc, tuple(callstack))
        self.decision_history[loc_key] = self.updated_decision_log(
            loc_key, decision)

        logger.log(
            hex(pc) + " : =" +  str(decision) + metric_str)

        return decision
