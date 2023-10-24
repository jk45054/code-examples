# posted by rolf rolles on stack exchange
# https://reverseengineering.stackexchange.com/questions/30132/how-to-print-disassembly-code-with-idapython-when-ida-doesn-t-detect-it-as-code

import ida_auto
import ida_bytes

def EnsureCode(ea):
    if ida_bytes.is_data(ida_bytes.get_flags(ea)):
        ida_bytes.del_items(ea,ida_bytes.DELIT_EXPAND)
    ida_auto.auto_wait()
    if not ida_bytes.is_code(ida_bytes.get_flags(ea)):
        ida_auto.auto_make_code(ea)
    ida_auto.auto_wait()
