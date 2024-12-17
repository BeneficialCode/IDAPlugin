from z3 import *
import ast
import astunparse
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.ir.translators.z3_ir import TranslatorZ3



x, y = BitVecs('x y', 64)

prove(x | y == x + (~x & y))

prove(x ^ y == x + y -2 * (x & y))

prove(x + y == (x | y) + (~x | y) - ~x)

mba_rewrite_or = "x + (~x & y)".replace('x', 'L').replace('y', 'R')
mba_rewrite_xor = "x + y -2 * (x & y)".replace('x', 'L').replace('y', 'R')
mba_rewrite_add = "(x | y) + (~x | y) - ~x".replace('x', 'L').replace('y', 'R')

print(mba_rewrite_or)
print(mba_rewrite_xor)
print(mba_rewrite_add)

simp = "(x | y) + (x ^ y)"
expr = ast.parse(simp, mode='eval')
print(ast.dump(expr,indent=4))

def bottomUpBFS(node):
    q = []
    q.append(node)

    bin_ops = []

    while q:
        cur = q.pop()

        if hasattr(cur, 'left'):
            q.append(cur.left)

        if hasattr(cur, 'right'):
            q.append(cur.right)

        if isinstance(cur, ast.BinOp):
            bin_ops.append(cur)

    return bin_ops

def rewriteMBA(root):
    bin_ops = bottomUpBFS(root)

    while bin_ops:
        cur = bin_ops.pop()

        new = None

        L = astunparse.unparse(cur.left)[:-1]
        R = astunparse.unparse(cur.right)[:-1]

        if isinstance(cur.op, ast.BitOr):
            new = ast.parse(mba_rewrite_or.replace('L', L).replace('R', R), mode='eval').body

        if isinstance(cur.op, ast.BitXor):
            new = ast.parse(mba_rewrite_xor.replace('L', L).replace('R', R), mode='eval').body

        if isinstance(cur.op, ast.Add):
            new = ast.parse(mba_rewrite_add.replace('L', L).replace('R', R), mode='eval').body

        if new:
            cur.op = new.op
            cur.left = new.left
            cur.right = new.right

        # print(astunparse.unparse(expr))

rewriteMBA(expr.body)
print(astunparse.unparse(expr))

x, y = BitVecs('x y', 64)
simp_z3 = (x | y) + (x ^ y)
obf2_z3 = ((((x + ((~ x) & y)) | ((x + y) - (2 * (x & y)))) + ((~ (x + ((~ x) & y))) | ((x + y) - (2 * (x & y))))) - (~ (x + ((~ x) & y))))
prove(simp_z3 == obf2_z3)

rewriteMBA(expr.body)
print(astunparse.unparse(expr))

rewriteMBA(expr.body)
print(astunparse.unparse(expr))

def getRaxExpr(file_path,start_addr):

    loc_db = LocationDB() # this is the symbol table
    container = Container.from_stream(open(file_path, "rb"),loc_db)
    machine = Machine(container.arch)
    mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db)
    lifter = machine.lifter_model_call(mdis.loc_db)
    asm_block = mdis.dis_block(start_addr)
    ira_cfg = lifter.new_ircfg()
    lifter.add_asmblock_to_ircfg(asm_block, ira_cfg)

    # Actually symbolically execute basic block
    sb = SymbolicExecutionEngine(lifter)
    sb.run_block_at(ira_cfg, start_addr)

    # return the expression for eax register
    return sb.eval_exprid(lifter.arch.regs.RAX)

file_path = "./scramble/x64/Release/scramble.exe"
addr = 0x1400011C0

rax_scramble = getRaxExpr(file_path, addr)
print("RAX scramble: ", rax_scramble)

translator = TranslatorZ3()

rax_scramble_z3 = translator.from_expr(rax_scramble)
rax = simplify(rax_scramble_z3)
print("SMT SIMLFIED RAX: ")
print(rax)


def test(RCX,RDX):
    return -((RCX + (RDX & (RCX ^ 0xFFFFFFFFFFFFFFFF))) ^ 0xFFFFFFFFFFFFFFFF) + ((RCX + RDX + -((RCX & RDX) << 0x1)) | (RCX + (RDX & (RCX ^ 0xFFFFFFFFFFFFFFFF)))) + ((RCX + RDX + -((RCX & RDX) << 0x1)) | ((RCX + (RDX & (RCX ^ 0xFFFFFFFFFFFFFFFF))) ^ 0xFFFFFFFFFFFFFFFF))

print(test(1234,5678))
