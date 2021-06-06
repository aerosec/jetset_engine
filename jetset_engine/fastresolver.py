import angr
from angr.analyses.cfg.indirect_jump_resolvers.resolver import IndirectJumpResolver

class FastResolver(IndirectJumpResolver):
    ''' 
    Indirect jump resolver that handles block local resolution
    i.e. it just symbolically executes the block of the jump, and if
    it can resolve the jump using only that block it does, else it fails
    '''
    def __init__(self, project):
        self.mapped_regions = [(obj.min_addr, obj.max_addr) for obj in project.loader.all_objects]
        super(FastResolver, self).__init__(project, timeless=False)
        
    def filter(self, cfg, addr, func_addr, block, jumpkind):
        ''' currently only supports boring jumps '''
        if jumpkind == 'Ijk_Boring':
            return True
        else:
            return False

    def is_mapped(self,curr_addr, addr):
        for lower,upper in self.mapped_regions:
            if (addr >= lower) and (addr <= upper):
                return True
        return False


    def resolve(self, cfg, addr, func_addr, block, jumpkind):
        resolver_state = self.project.factory.entry_state(addr=block.addr)
        resolver_state.solver._solver.timeout = 300 # .3 seconds
        successors = resolver_state.step()
        # if its too low it was likely a mistake
        valid_targets = [succ.addr for succ in successors if self.is_mapped(addr,succ.addr)]
        # only resolve if we are sure, i.e. not too many outputs
        if len(valid_targets) <= 8 and len(valid_targets) > 0:
            print("resolving succeeded: ",hex(addr), [hex(target) for target in valid_targets] )
            return True, valid_targets
        else:
            return False, None
