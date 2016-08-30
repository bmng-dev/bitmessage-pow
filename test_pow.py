import ctypes
import hashlib

payload = '\x00'
time_to_live = 300
trials = 1000
padding = 1000

lib = ctypes.CDLL('bmpow32.dll')

lib.BitmessagePOW.argtypes = [ctypes.c_char_p, ctypes.c_uint64]
lib.BitmessagePOW.restype = ctypes.c_uint64

payload = payload[:2**18]
adjustedLength = len(payload) + padding
digest = hashlib.sha512(payload).digest()
target = 2 ** 64 / (trials * (adjustedLength + ((time_to_live * adjustedLength) / (2 ** 16))))

nonce = lib.BitmessagePOW(digest, target)
print hex(nonce)
