import os

def xor_encrypt(plain_text: str) -> (bytes, bytes):
    plain_bytes = plain_text.encode('utf-8')
    
    key = os.urandom(max(128, len(plain_bytes)))
    
    encrypted_bytes = bytes([b ^ key[i % len(key)] for i, b in enumerate(plain_bytes)])
    
    return encrypted_bytes, key

def format_for_rust(byte_data: bytes) -> str:
    rust_array = ', '.join(f'{b}' for b in byte_data)
    return f"vec![{rust_array}]"

plain_text = "bctf{c0mp1l1n6_ru57_m4k35_my_4ud10_570p_w0rk1n6_2a14bdd6fa28e02d}"
ciphertext, key = xor_encrypt(plain_text)
print("Encrypted:", format_for_rust(ciphertext))
print("Key:", format_for_rust(key))
