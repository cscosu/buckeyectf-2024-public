from xnor import xnor_bytes

encrypted_message = bytes.fromhex(
    "fe9d88f3d675d0c90d95468212b79e929efffcf281d04f0cfa6d07704118943da2af36b9f8"
)
encrypted_flag = bytes.fromhex(
    "de9289f08d6bcb90359f4dd70e8d95829fc8ffaf90ce5d21f96e3d635f148a68e4eb32efa4"
)
message = b"Blue is greener than purple for sure!"

key = xnor_bytes(encrypted_message, message)
print(key.hex())
flag = xnor_bytes(encrypted_flag, key)

print(flag)
