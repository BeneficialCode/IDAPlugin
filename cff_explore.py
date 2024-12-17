# -*- coding: utf-8 -*-
from miasm.analysis.machine import Machine
from miasm.arch.x86.arch import mn_x86
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import ExprCond, ExprId, ExprInt, ExprMem 
from miasm.expression.simplifications import expr_simp
from miasm.arch.x86.regs import *
from miasm.core import parse_asm, asmblock
from miasm.core.locationdb import LocationDB
from miasm.analysis.binary import Container
from miasm.analysis.simplifier import IRCFGSimplifierCommon
from future.utils import viewitems
from miasm.loader.strpatchwork import *
from miasm.ir.translators.translator import Translator
import warnings
import z3
import pydotplus
from IPython.display import Image, display_png


class FinalState:
    def __init__(self, result, sym, path_conds, path_history):
        self.result = result
        self.sb = sym
        self.path_conds = path_conds
        self.path_history = path_history


def explore(ir, start_addr, start_symbols, 
        ircfg, cond_limit=30, uncond_limit=100, 
        lbl_stop=None, final_states=[]):

    def codepath_walk(addr, symbols, conds, depth, final_states, path):

        if depth >= cond_limit:
            warnings.warn("'depth' is over the cond_limit :%d"%(depth))
            return 

        sb = SymbolicExecutionEngine(ir, symbols)

        for _ in range(uncond_limit):

            if isinstance(addr, ExprInt): 
                if addr == lbl_stop:
                    final_states.append(FinalState(True, sb, conds, path))
                    return

            path.append(addr)

            pc = sb.run_block_at(ircfg, addr)

            if isinstance(pc, ExprCond): 
    
                # Calc the condition to take true or false paths
                cond_true  = {pc.cond: ExprInt(1, 32)}
                cond_false = {pc.cond: ExprInt(0, 32)}

                # The destination addr of the true or false paths
                addr_true  = expr_simp(
                    sb.eval_expr(pc.replace_expr(cond_true), {}))

                addr_false = expr_simp(
                    sb.eval_expr(pc.replace_expr(cond_false), {}))

                # Need to add the path conditions to reach this point
                conds_true = list(conds) + list(cond_true.items())
                conds_false = list(conds) + list(cond_false.items())

                # Recursive call for the true or false path
                codepath_walk(
                        addr_true, sb.symbols.copy(), 
                        conds_true, depth + 1, final_states, list(path))

                codepath_walk(
                        addr_false, sb.symbols.copy(), 
                        conds_false, depth + 1, final_states, list(path))

                return
            else:
                addr = expr_simp(sb.eval_expr(pc))

        final_states.append(FinalState(True, sb, conds, path))
        return 

    return codepath_walk(start_addr, start_symbols, [], 0, final_states, [])


filename = 'test-mod2-fla.bin'
target_addr = 0x8048440  

loc_db = LocationDB()
with open(filename, 'rb') as fstream:
    cont = Container.from_stream(fstream, loc_db)
machine = Machine(cont.arch)

mdis = machine.dis_engine(cont.bin_stream, loc_db=cont.loc_db)
asmcfg = mdis.dis_multiblock(target_addr)
ir_arch = machine.ira(mdis.loc_db)
ircfg = ir_arch.new_ircfg_from_asmcfg(asmcfg)


# Apply simplifier
common_simplifier = IRCFGSimplifierCommon(ir_arch)
common_simplifier.simplify(ircfg, target_addr)

# Visualize the CFG
with open('cfg.dot', 'w') as f:
    f.write(ircfg.dot())
graph = pydotplus.graphviz.graph_from_dot_file('cfg.dot')
graph.write_png('cfg.png')
display_png(Image(graph.create_png()))

symbols_init =  {
    ExprMem(ExprId('ESP_init', 32), 32) : ExprInt(0xdeadbeef, 32)
}

for i, r in enumerate(all_regs_ids):
    symbols_init[r] = all_regs_ids_init[i]

final_states = []


explore(ir_arch, 
        target_addr, 
        symbols_init, 
        ircfg, 
        lbl_stop=0xdeadbeef, 
        final_states=final_states)

# Show results
print('final states:', len(final_states))

for final_state in final_states:
    if final_state.result:
        print('Feasible path:','->'.join([str(x) for x in final_state.path_history]))
        print('\t',final_state.path_conds)
    else:
        print('Infeasible path:','->'.join([str(x) for x in final_state.path_history]))
        print('\t',final_state.path_conds)

    final_state.sb.dump(ids=False)
    print('')