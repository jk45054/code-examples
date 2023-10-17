from ida_bytes import get_bytes
base_address = 0x1c0000
size = 0x10000
filename = "debug034.bin"
with open(filename, "wb") as f:
  f.write(get_bytes(base_address, size))
f.close()
