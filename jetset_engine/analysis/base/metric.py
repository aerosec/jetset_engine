import networkx as nx
from fastresolver import FastResolver
from analysis.debug import *
from collections import defaultdict
from analysis.distance import reverse_topo_cg, call_edges_opt, is_trivial_func, get_jumpout_target

#abstract metric class
class Metric():
    def __init__(self):
        raise Exception("Unimplemented")

    def get_score(self, state):
        raise "Unimplemented"

class L1Metric(Metric):
    def __init__(self, cfg, find):
        self.cfg = cfg
        self.find_point = find
        self.target_block = cfg.get_node(find)
        self.visited = set()
        if self.target_block: # if we haven't found the target, don't bother to do distance stuff
            self.update_distance_structures(self.cfg)


    def get_score(self, addr, callstack, visit=False):
        return self.lazy_get_score(addr,callstack)

    def update_distance_structures(self, cfg):
        self.t_callchain_index = self.mk_t_callchain_index(cfg)
        self.mk_local_score_index(cfg)

    def get_top_of_callchain(self, cfg, target_faddr):
        if self.p.entry in cfg.kb.callgraph and nx.has_path(cfg.kb.callgraph, self.p.entry, target_faddr):
            return self.p.entry
        tops = []
        for faddr in cfg.kb.callgraph:
            preds =  list(cfg.kb.callgraph.predecessors(faddr))
            if not preds:
                if nx.has_path(cfg.kb.callgraph, faddr, target_faddr):
                    tops.append(faddr)
        if len(tops) == 1:
            return tops[0]
        else:
            assert(False)


    # cfg -> { faddr -> [[faddr]] }
    def mk_t_callchain_index(self, cfg):
        '''
        Construct a mapping from each function to the set of callpaths
        from that function that lead to the target block.
        In this sense, it tells the distance function whether it should
        follow calls, or just exit via a return.
        '''
        if not cfg.get_node(self.find_point):
            return {}
        t_callchain_index = defaultdict(list)
        target_faddr = cfg.get_node(self.find_point).function_address

        top_of_callchain = self.get_top_of_callchain(cfg,target_faddr)
        entry_faddr = cfg.get_node(top_of_callchain).function_address
        all_paths = list(nx.all_simple_paths(cfg.kb.callgraph, source=entry_faddr, target=target_faddr,cutoff=8))
        for path in all_paths:
            for idx,faddr in enumerate(path):
                if faddr != target_faddr:
                    callpath = path[idx+1:]
                    if callpath not in t_callchain_index[faddr]:
                        t_callchain_index[faddr].append(callpath)
        return dict(t_callchain_index)

    def weight_func_graph(self, func):
        for src,dst,call_target in call_edges_opt(func):
            if call_target != None: # is a call edge
                if call_target in self.local_score_index:
                    func.graph[src][dst]['weight'] = self.local_score_index[call_target] + 1
                else:
                    func.graph[src][dst]['weight'] = 2
            else:
                func.graph[src][dst]['weight'] =  1

    def tail_call_dists(self, func, tail_calls):
        dists_to_exits = []
        for tail_call in tail_calls:
            call_target = tail_call.successors()[0].addr
            if call_target in self.local_score_index:
                target_score = self.local_score_index[call_target]
            else:
                target_score = REALLY_BIG_NUMBER
            dists = dict(nx.shortest_path_length(func.graph,  target=tail_call, weight='weight'))
            for baddr in dists:
                dists[baddr] += target_score
            dists_to_exits.append(dists)
        return dists_to_exits

    # function -> [blocknodes] -> {int (block address) -> int (score)}
    def mk_local_dists(self, func, exits):
        assert(exits)
        (rets,tail_calls) = exits

        local_dists = {}
        dists_to_rets = [dict(nx.shortest_path_length(func.graph,  target=exit, weight='weight')) for exit in rets]
        dists_to_tail_calls = self.tail_call_dists(func, tail_calls)
        dists_to_exits = []
        dists_to_exits.extend(dists_to_rets)
        dists_to_exits.extend(dists_to_tail_calls)

        # aggregate shortest distance to each of these
        for dists_to_exit in dists_to_exits:
            for block,dist_to_exit in dists_to_exit.items():
                baddr = block.addr
                curr_dist = local_dists.get(baddr)
                if curr_dist != None:
                    local_dists[baddr] = min(curr_dist, dist_to_exit)
                else:
                    local_dists[baddr] = dist_to_exit
        return local_dists

    def get_func_exits(self, cfg, func):
        '''
        Get the function exits that we are interested in.
        It will check for exits in the following order:
        1. the target block is in this function
        2. calls leading to target function
        3. return sites
        4. callout and jumpout sites (signifying a tail call)
        '''
        faddr = func.addr
        rets = []
        tail_calls = []

        if cfg.get_node(self.find_point):
            target_faddr = cfg.get_node(self.find_point).function_address
            if faddr == target_faddr:
                return ([func.get_node(self.find_point)],[])

        if faddr in self.t_callchain_index:
            next_faddrs = [callchain[0] for callchain in self.t_callchain_index[faddr]]

            rets.extend([func.get_node(callsite) for callsite in func.get_call_sites()
                        if func.get_call_target(callsite) in next_faddrs])
            j_exits = [jumpout_site for jumpout_site in func.jumpout_sites
                       if get_jumpout_target(jumpout_site) in next_faddrs]
            tail_calls.extend(j_exits)
        else:
            rets.extend(func.ret_sites)
            tail_calls.extend(func.callout_sites)
            tail_calls.extend(func.jumpout_sites)

        return (rets,tail_calls)

    def update_local_score_index(self, local_dists):
        for baddr, local_dist in local_dists.items():
            if baddr in self.local_score_index:
                raise Exception("Duplicate Block in local score index")
            self.local_score_index[baddr]  = local_dist


    # cfg -> { block -> int (score) }
    def mk_local_score_index(self, cfg):
        '''
        Constructs a mapping between blocks in functions -> distance.
        This distance represents the distance from the current node to
        the ideal exit from the current function. These local scores can
        then be lazily chained together to get an accurate distance to the target.
        '''

        self.local_score_index = {}
        for faddr in reverse_topo_cg(cfg):
            func = cfg.functions[faddr]
            if is_trivial_func(func):
                continue
            exits = self.get_func_exits(cfg, func)
            if not exits:
                continue
            self.weight_func_graph(func)
            local_dists = self.mk_local_dists(func, exits)

            self.update_local_score_index(local_dists)

    # [faddr] -> int
    def path_dist(self, path):
        score = 0
        for faddr in path:
            score += self.local_score_index[faddr]
        return score

    # faddr -> int (score)
    def callchain_distance(self, faddr):
        if faddr not in self.t_callchain_index:
            return REALLY_BIG_NUMBER
        paths = self.t_callchain_index[faddr]
        path_dists = [self.path_dist(path) for path in paths]
        return min(path_dists)

    # state -> int (score)
    def lazy_get_score(self, addr, callstack):
        '''
        This is ran at calltime to compute a distance function to
        the target block from the current state.
        The total score is equal to the sum of the costs to return from all functions in order
        to get to  a callsite to the target block + sum of distances to all calls in that callchain.
        Consult paper for formal definition. If this has not been put in the paper yet, ask
        Evan to do so.
        '''
        try:
            baddr = self.block_index[addr] # basic block addr for current state
        except:
            print("self.addr not in self.block_index???")
        curr_faddr = self.cfg.get_node(baddr).function_address # initialize in case of empty callstack
        
      
        assert(self.local_score_index)
        try:
            score = self.local_score_index[baddr]
        except:
            return REALLY_BIG_NUMBER


        prev_ret_addr = baddr
        # callstack distance
        # prev_ret_addr stuff is to deal with tail calls
        for ret_addr in reversed(callstack):
            # if we trace our way up to empty call frame
            if ret_addr == None or ret_addr == 0:
                break

            if curr_faddr in self.t_callchain_index and self.t_callchain_index[curr_faddr] != []:
                break
            
            # To compensate for tail calls (since that will involve two stack frames that return to same place)
            if ret_addr == prev_ret_addr:
                continue
            prev_ret_addr = ret_addr

            try:
                curr_faddr = self.cfg.get_node(ret_addr).function_address # address of function that callsite belongs to
            except:
                return REALLY_BIG_NUMBER

            try:
                score += self.local_score_index[ret_addr]
            except:
                pass

        # callchain distance
        # if we are not in the target function, add callchain distance
        if  self.cfg.get_node(self.find_point) and curr_faddr != self.cfg.get_node(self.find_point).function_address:
            callchain_dist =  self.callchain_distance(curr_faddr)
            score += callchain_dist

        return score
