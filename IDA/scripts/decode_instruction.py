import ida_ua
import ida_kernwin
ea = ida_kernwin.get_screen_ea()
insn = ida_ua.insn_t()
len_inst = ida_ua.decode_insn(insn, ea)
if len_inst > 0:
  print(f"get_canon_mnem: {insn.get_canon_mnem()}")
  print(f"get_canon_feature: {insn.get_canon_feature()}")
  print(f"itype: {insn.itype}")
  # Opx is of type op_t
  print(f"op1: {insn.Op1}")
  print(f"op2: {insn.Op2}")
  print(f"op3: {insn.Op3}")
  
