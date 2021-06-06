from idautils import *
from idaapi import *
from idc import *
blockCount = 0
for segea in Segments():
  for funcea in Functions(segea, SegEnd(segea)):
    f = get_func(funcea)
    fc = FlowChart(f)
    for b in fc:
      blockCount += 1
print(blockCount)

