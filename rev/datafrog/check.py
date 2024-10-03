import subprocess

FLAG = b"bctf{l0g1c_pr0gr4mm1ng_i5_c00l_i_guess_e8969966bEBIHCFDGAHCFDGAEBIDGAEBIHCFBADCIEGFHGFHBADCIECIEGFHBADIDBFECAHGAHGIDBFECFECAHGIDB5e70062e84212f1d863ac11386e48e46d160c0}"
def check(flag):
    p = subprocess.run(["./target/release/datalog1"], input=flag, stdout=subprocess.PIPE)
    if b"Congratulations" in p.stdout:
        print("pass")
        return True
    print("fail")
    return False

assert check(FLAG)
for i in range(len(FLAG)):
    flag = FLAG[:i] + bytes([FLAG[i]+1]) + FLAG[i+1:]
    assert not check(flag)
    flag = FLAG[:i] + bytes([FLAG[i]-1]) + FLAG[i+1:]
    assert not check(flag)