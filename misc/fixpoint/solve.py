import os
import base64

given_alphabet = "bctf{?????????????????????????FiXed???????????????????????p01nT}"
fixed_point = "NslSBwm6YNHHNreCNsmojw8zY9nGVzep9NoJ5LHpH3b8NKnQlB2Ca{XzIxeUyR85Y{COjRD09P4mFEAAFACZlAo0jwnGBrj7UAbwYBHDjBDEjBlMY{DWkE46YrVtaKh6ABDdVLoty{5Gjr5DMrmSNAo05DVu5NjR93m9VEDqMfHcjr5rAr2WVPo0lBVGaxA{N3mvBw8cYzbL5DHLlB8GBxrzYNo95B52N9HCIR4Ol3mcaxm3AocWkE2tArVeF{D0NxlvVrm6UElHFKmklB5CNE2tU{VtFPmp9B8WUNAtlNmUUBefyACwNR7zY9leFEwzj9nxARvDks5caoHo5sv{k{8ZYPH9aKwRABASy{HqY9vSjxAfNrBOVDA0As5EBEL7UBCZALAUj35SNKLAABmoHsocj6VUBxVp9NoSHBHDV64GU98ZjAmR5Evzl9leYweWl3lRFRv0UD4HB{X8IBv6BrDtjAl8Fwe29NoRBR4Zj9HUarmgAr5ck{DzlBAt5B76ABmf9rDkjAAGkzANNrvkjBDtY9nCaRnxMxH9ABmZAsb8NKnNy{mC5DIRl{VAUNeMMrDvBxADVs4SU92o93VoAR7zYDmEBsI7ABjwy{m09femjsIRjsm{VE4cYfeEVRBOUB8WBrmylD4GUBeAI3mvHwDOl9luFw5pY{mcVfAtlzHcjKLKU3m{MR4cjBVuFrDUNsmRMR4t5P5HU98fIAmJF{LZyfocjKLMj3ldU{8qYr88FRLflB5mBK20ArDANKAlN3m{VrmZjB59az5NANrOYzrzAKncBxVp9B5v5BmzyNVcjK46F3vvkfoKH9LGawoyMslvFLHDlElHHKADAomtNLAtUDVtaKL8Y{jw5LAtHBDmkRLRyPV{NR78YPAEVzA793vvILHKj35SFrexMrvkyLBzY3vlBx5xMrm9VBHO5DAUaRLyNACwVfAjlBeAUNeKyBDvyrH0ND48HKnxMrvkN9hzYE5AFze293CZU{Hy"

def solve(data: bytes):
    alphabet = [None if x == '?' else ord(x) for x in given_alphabet]
    j = 0
    result = ''
    for i in range(0, len(data), 3):
        three_bytes = data[i:i+3]
        x = int.from_bytes(three_bytes.ljust(3, b'\x00'), 'big')
        a = (x & 0b111111000000000000000000) >> 18
        b = (x & 0b000000111111000000000000) >> 12
        c = (x & 0b000000000000111111000000) >> 6
        d = (x & 0b000000000000000000111111) >> 0
        four_base64_digits = [a, b, c, d]
        for base64_digit in four_base64_digits:
            if j < len(data):
                alphabet[base64_digit] = data[j]
            j += 1
        
    
    return alphabet

    
print(''.join(chr(x) if x else '?' for x in solve(fixed_point.encode())))
