import networkx as nx 
import angr


def get_jumpout_target(jumpout_site):
    targets = [block.addr for block in jumpout_site.successors()]
    if len(targets) >= 1:
        return targets[0]
    else:
        assert(False)

def get_ret_sites(func):
    return [empty_key(ret_site) for ret_site in func.ret_sites]


def get_succ_func(block): 
    targets = [] 
    for succ in block.successors(): 
        if type(succ) == angr.knowledge_plugins.functions.function.Function: 
            targets.append(succ.addr) 
    return targets 

def remove_backedges(cg): 
    while True: 
        try: 
            backedge = nx.find_cycle(cg)[0] 
        except nx.NetworkXNoCycle: 
            return 
        cg.remove_edge(backedge[0],backedge[1]) 

def is_trivial_func(func):
    for block in func.blocks:
        if block.size > 0:
            return False
    return True

def reverse_topo_cg(cfg):
    ''' 
    return functions in callgraph in reverse topological order
    currently fails if the callgraph has cycles
    '''
    cg = cfg.kb.callgraph 
    self_edges = list([edge for edge in nx.selfloop_edges(cg)]) 
    cg.remove_edges_from( self_edges )  
    remove_backedges(cg)
    try:
        order = list(reversed(list(nx.topological_sort(cg))))     
    except Exception as e:
        print(e)
    return order                

def get_node(graph, target):
    ''' linear scan for a node with a particular address in graph'''
    for callstack_key,node in graph.node:
        if node.addr == target:
            return (callstack_key,node)

# func -> [ (node, target, call_target) ] 
def call_edges(func):
    ''' return list of call edges within a function'''
    edges = []
    for node in func.graph.nodes:  
        out_edges = func.graph[node]  
        for target in out_edges:
            # get all calls in function  
            call_targets = get_succ_func(node) 
            if len(call_targets) == 1:
                edges.append( (node,target,call_targets[0]) )
    return edges


def call_edges_opt(func):
    edges = []
    for node in func.graph.nodes:  
        out_edges = func.graph[node]  
        for target in out_edges:
            call_targets = get_succ_func(node) 
            if len(call_targets) == 1:
                edges.append( (node,target,call_targets[0]) )
            else:
                edges.append( (node,target,None) ) 
    return edges
