from datetime import datetime
def base_stats(dev):
  print("num writes: ", len([v for v in dev.trace if (v.is_ioport or v.is_mmio) and not v.is_read]))
  print("num reads", len([v for v in dev.trace if (v.is_ioport or v.is_mmio) and v.is_read]))
  print("num distinct write addrs: ", len(set([(v.addr if v.is_mmio else v.portno) for v in dev.trace if (v.is_ioport or v.is_mmio) and not v.is_read])))
  print("num distinct read addrs: ", len(set([(v.addr if v.is_mmio else v.portno) for v in dev.trace if (v.is_ioport or v.is_mmio) and v.is_read])))

def constraint_stats(dev):
  import statistics
  vars = [v for v in dev.trace if (v.is_ioport or v.is_mmio) and v.is_read]
  sums = []
  ics = dev.solver.independent_constraints()
  for v in vars:
    s = list(v.symbol.variables)[0]
    sums.append(sum([len(c[1]) for c in ics if s in c[0]]))
  print("average constraints per variable:",statistics.mean(sums))

def count_trace_lens(dev):
  from collections import Counter
  import statistics
  v1 = list(Counter([v.addr for v in dev.trace if (v.is_mmio) and v.is_read]).values())
  v2 = list(Counter([v.portno for v in dev.trace if (v.is_ioport) and v.is_read]).values())
  tot = v1 + v2
  print(statistics.mean(tot))
  print(statistics.median(tot))
  print(max(tot))

