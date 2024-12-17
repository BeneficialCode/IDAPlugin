from z3 import *

x = BitVec("x",64)

solver = Solver()

solver.add(x>10)
solver.add(x-23<10)
solver.add(x*3<100)

if solver.check() == sat: print(solver.model())

