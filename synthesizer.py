from msynth import Simplifier
import ast
import astunparse
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.ir.translators.z3_ir import TranslatorZ3

oracle_path = './oracle.pickle'

simplifier = Simplifier(oracle_path)

file_path = "./scramble/x64/Release/scramble.exe"
addr = 0x1400011C0

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

rax_scramble = getRaxExpr(file_path, addr)
print("RAX scramble: ", rax_scramble)

rax_scramble_synth = simplifier.simplify(rax_scramble)
print("RAX scramble synth: ", rax_scramble_synth)