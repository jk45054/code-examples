from ida_bytes import patch_bytes
base_address = 0x1cfe00
buf = b"QUFBQUJCQkJDQ0NDREREREVFRUVGRkZGR0dHR0hISEhJSUlJSkpKSktLS0tMTExM"
patch_bytes(base_address, buf)
