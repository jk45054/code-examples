# Decode Instruction at ScreenEA
import ida_ua
import ida_kernwin
ea = ida_kernwin.get_screen_ea()
insn = ida_ua.insn_t()
len_inst = ida_ua.decode_insn(insn, ea)
if len_inst > 0:
  print(insn.get_canon_mnem())
