# -*- coding: utf-8 -*-
from miasm.analysis.machine import Machine
from miasm.arch.x86.arch import mn_x86
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import ExprInt, ExprMem, ExprId, LocKey
from miasm.expression.expression import ExprCond
from miasm.expression.simplifications import expr_simp
from miasm.arch.x86.regs import *
from miasm.analysis.binary import Container
from miasm.core.locationdb import LocationDB
from future.utils import viewitems
from argparse import ArgumentParser
import sys, z3
import warnings

class FinalState:
    def __init__(self,result,sym,path_conds,path_history):
        self.result = result
        self.sb = sym
        self.path_conds = path_conds
        self.path_history = path_history

def explore(ir,start_addr,start_symbols,ircfg,cond_limit=30,uncond_limit=100,
            lbl_stop=None,final_states=[]):
    def codepath_walk(addr,symbols,conds,depth,final_states,path):
        if depth >= cond_limit:
            warnings.warn('depth is over the cond_limit')
            return
        
        sb = SymbolicExecutionEngine(ir,symbols)

        for _ in range(uncond_limit):
            if isinstance(addr,ExprInt):
                if addr == lbl_stop:
                    final_states.append(FinalState(True,sb,conds,path))
                    return
                
        path.append(addr)

        pc = sb.run_block_at(ircfg,addr)

        if isinstance(pc,ExprCond):

            # Calc the condition to take true or false paths
            conds_true = {pc.cond: ExprInt(1,32)}
            conds_false = {pc.cond: ExprInt(0,32)}

            # the destination addr of the true or false paths
            addr_true = expr_simp(sb.eval_expr(pc.replace_expr(conds_true),{}))
            addr_false = expr_simp(sb.eval_expr(pc.replace_expr(conds_false),{}))


            codepath_walk(
                    addr_true, sb.symbols.copy(), 
                    conds_true, depth + 1, final_states, list(path))

            codepath_walk(
                    addr_false, sb.symbols.copy(), 
                    conds_false, depth + 1, final_states, list(path))

            return
        else:
            addr = expr_simp(sb.eval_expr(pc))

        final_states.append(FinalState(True,sb, conds,path))
        return
    return codepath_walk(start_addr, start_symbols, [], 0, final_states, [])


def to_idc(lockkeys,asmcfg):
    header = '''
#include <idc.idc>
static main(){
'''
    footer = '''
}
'''

    body = ''
    f = open('op-color.idc','w')
    for lbl in lockkeys:
        asmblk = asmcfg.loc_key_to_block(lbl)
        if asmblk:
            for l in asmblk.lines:
                body += 'SetColor(0x%08X,CIC_ITEM,0xc7c7ff);\n'%(l.offset)

    f.write(header + body + footer)
    f.close()

filename = 'x-tunnel.bin'
target_addr = 0x405710
idc = True
loc_db = LocationDB()
with open(filename, "rb") as fstream:
    cont = Container.from_stream(fstream,loc_db)

machine = Machine(cont.arch)
mdis = machine.dis_engine(cont.bin_stream,follow_call=False,loc_db=cont.loc_db)
ir_arch = machine.lifter_model_call(mdis.loc_db)

# Disassemble the targeted function
asmcfg = mdis.dis_multiblock(target_addr)

ircfg = ir_arch.new_ircfg_from_asmcfg(asmcfg)
for lbl,irblk in viewitems(ircfg.blocks):
    print(irblk)

# Preparing the intial symbols for regs and mems
symbols_init = {}

for i,r in enumerate(all_regs_ids):
    symbols_init[r] = all_regs_ids_init[i]

# for mems
# 0xdeadbeef is the mark to stop the exploring
symbols_init[ExprMem(ExprId('ESP_init', 32), 32)] = ExprInt(0xdeadbeef, 32)

final_states = []

explore(ir_arch, 
        target_addr, 
        symbols_init, 
        ircfg, 
        lbl_stop=0xdeadbeef, 
        final_states=final_states)

executed_lockey   = []
unexecuted_lockey = []

# The IR nodes which are included in one of paths were executed.
for final_state in final_states:
    if final_state.result:
        for node in final_state.path_history:
            if isinstance(node, int):
                lbl = ircfg.get_loc_key(node)
            elif isinstance(node, ExprInt):
                lbl = ircfg.get_loc_key(node)
            elif isinstance(node, LocKey):
                lbl = node.loc_key

            if lbl not in executed_lockey:
                executed_lockey.append(lbl)


# Otherwise, the IR nodes which are not included in any path were not executed.
for lbl, irblock in viewitems(ircfg.blocks):
    if lbl not in executed_lockey:
        unexecuted_lockey.append(lbl)

print(executed_lockey)
print(unexecuted_lockey)
print('len(executed_lockey):', len(executed_lockey))
print('len(unexecuted_lockey):', len(unexecuted_lockey))

# It colors opaque predicates
if idc:
    to_idc(unexecuted_lockey, asmcfg)