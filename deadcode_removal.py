from miasm.analysis.machine import Machine
from miasm.arch.x86.arch import mn_x86
from miasm.core import parse_asm, asmblock
from miasm.core.locationdb import LocationDB
from future.utils import viewitems
from miasm.analysis.data_flow import *
import pydotplus
from IPython.display import Image,display_png
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.loader.strpatchwork import *

loc_db = LocationDB()
asmcfg = parse_asm.parse_txt(mn_x86, 32, '''
main:
    PUSH EBP
    MOV EBP, ESP
    MOV ECX, 0x23
    MOV ECX, 0x4
    MOV EAX, ECX
    POP EBP
    RET
''',loc_db)
loc_db.set_location_offset(loc_db.get_name_location("main"),0x0)

patches = asmblock.asm_resolve_final(mn_x86, asmcfg)
patch_worker = StrPatchwork()
for offset, raw in patches.items():
    patch_worker[offset] = raw

machine = Machine('x86_32')
ir_arch = machine.ira(loc_db)
ircfg = ir_arch.new_ircfg_from_asmcfg(asmcfg)
print('Before Simplification: ')
for lbl, irb in viewitems(ircfg.blocks):
    print(irb)
dead_rm = DeadRemoval(ir_arch)
dead_rm(ircfg)
print('After Simplification: ')
for lbl, irb in viewitems(ircfg.blocks):
    print(irb)