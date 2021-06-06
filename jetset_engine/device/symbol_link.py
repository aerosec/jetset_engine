class SymbolLink:
    def __init__(self):
        self.linked_vars = {}

    def resolve_link(self, var):
        if var != self.linked_vars[var]:
            self.linked_vars[var] = self.resolve_link(self.linked_vars[var])
        return self.linked_vars[var]

    def link_var2(self, var1, var2):
        if var1 in self.linked_vars:
            if var2 in self.linked_vars:
                self.linked_vars[self.resolve_link(var1)] = self.resolve_link(var2)
            else:
                self.linked_vars[var2] = self.resolve_link(var1)
        else:
            if var2 in self.linked_vars:
                self.linked_vars[var1] = self.resolve_link(var2)
            else:
                self.linked_vars[var1] = self.linked_vars[var2] = var1

    def link_varn(self, *vars):
        for i in range(len(vars) - 1):
            self.link_var2(vars[i], vars[i + 1])

    def vars_linked(self, var1, var2):
        if var1 == var2:
            return True
        if var1 not in self.linked_vars:
            return False
        if var2 not in self.linked_vars:
            return False
        return self.resolve_link(var1) == self.resolve_link(var2)
