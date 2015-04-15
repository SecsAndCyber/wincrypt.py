from ctypes import *
wintrust_dll = windll.LoadLibrary("wintrust.dll")
crypt32_dll = windll.LoadLibrary("Crypt32.dll")

windll.kernel32.GetLastError.restype = c_uint
GetLastError = windll.kernel32.GetLastError

free = cdll.msvcrt.free
malloc = cdll.msvcrt.malloc
malloc.restype = POINTER(c_ubyte)
malloc.argtype = [c_uint]

def Reverse( _dict, item, justone=False ):
    keys = []
    if item in _dict.values():
        for key in _dict:
            if item == _dict[key]:
                keys.append(key)
    if justone and keys:
        return keys[0]
    return keys
    
def BinPrint( data ):
    r = []
    for d in data:
        r.append( chr(d) if ord('0') < d < ord('z') else "." )
    return "".join(r)
    