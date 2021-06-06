import networkx as nx
from analysis.debug import *


class ConstraintSlicer(object):
    """docstring for ConstraintSlicer"""
    def __init__(self, device):
        super(ConstraintSlicer, self).__init__()
        self.group_ids = {}  # symbol_id -> group_id
        self.symbol_groups = {}  # group id -> set(symbol_idx)
        self.device = device

    def add_symbol(self, sym_idx):
        self.group_ids[sym_idx] = sym_idx
        self.symbol_groups[sym_idx] = set([sym_idx])

    def get_symbol(self, v):
        if v.op == 'Extract':
            return self.get_symbol(v.args[2])
        else:
            return self.device.idx_map[v.args[0]]

    def add_binop_deps(self, dst, v0, v1):
        if type(v0) != int:
            symbol0 = self.get_symbol(v0)
            self.union(dst, symbol0)
        if type(v1) != int:
            symbol1 = self.get_symbol(v1)
            self.union(dst, symbol1)

    def add_unop_deps(self, dst, v):
        if type(v) != int:
            symbol = self.get_symbol(v)
            self.union(dst, symbol)

    def add_decision_deps(self, v0, v1):
        if type(v0) != int and type(v1) != int:
            symbol0 = self.get_symbol(v0)
            symbol1 = self.get_symbol(v1)
            self.union(symbol0, symbol1)

    def find(self, v):
        group_id = self.group_ids[v]
        return self.symbol_groups[group_id]

    def union(self, v0, v1):
        group_id0 = self.group_ids[v0]
        group_id1 = self.group_ids[v1]
        group0 = self.symbol_groups[group_id0]
        group1 = self.symbol_groups[group_id1]
        if len(group0) >= len(group1):
            for v in group1:
                self.group_ids[v] = group_id0
            del self.symbol_groups[group_id1]
            self.symbol_groups[group_id0] = group0.union(group1)
        else:
            for v in group0:
                self.group_ids[v] = group_id1
            del self.symbol_groups[group_id0]
            self.symbol_groups[group_id1] = group1.union(group0)

    def vars_in_constraint(self, constraint):
        return set([
            self.get_symbol(thing) for thing in constraint.leaf_asts()
            if thing.symbolic
        ])

    def constraint_in_component(self, component, constraint):
        vars_included = self.vars_in_constraint(constraint)
        return (component.intersection(vars_included) != set())

    def slice_constraint(self, constraints, v0, v1):
        related_vars = set()
        if type(v0) != int:
            symbol0 = self.get_symbol(v0)
            group0 = self.find(symbol0)
            related_vars = related_vars.union(group0)
        if type(v1) != int:
            symbol1 = self.get_symbol(v1)
            group1 = self.find(symbol1)
            related_vars = related_vars.union(group1)

        new_constraints = [
            constraint for constraint in constraints
            if self.constraint_in_component(related_vars, constraint)
        ]
        return new_constraints
