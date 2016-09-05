import os
import sys

platform = os.environ.get('PLATFORM', '').lower()
interpreter_bits = (sys.maxsize.bit_length() + 7) / 8 * 8

if platform == 'x64' and interpreter_bits != 64:
   raise SystemExit

if platform in ['win32', 'x86'] and interpreter_bits != 32:
   raise SystemExit


import ctypes
import hashlib
import logging
import struct
import timeit

logging.basicConfig(format='%(levelname)8s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

Q_BE = struct.Struct('>Q')
Q_LE = struct.Struct('<Q')

payload = '\x00' * 4
time_to_live = 300
trials = 1000
padding = 1000

payload = payload[:2**18]
adjustedLength = len(payload) + padding
digest = hashlib.sha512(payload).digest()
target = 2 ** 64 / (trials * (adjustedLength + ((time_to_live * adjustedLength) / (2 ** 16))))
target_bytes = Q_BE.pack(target)

def do_pow_py_be():
    message = bytearray(8 + len(digest))
    message[8:] = digest
    for nonce in xrange(0x7FFFFFFF):
        Q_BE.pack_into(message, 0, nonce)
        if 0 >= cmp(hashlib.sha512(hashlib.sha512(message).digest()).digest(), target_bytes):
            return nonce

def do_pow_py_le():
    message = bytearray(8 + len(digest))
    message[8:] = digest
    for nonce in xrange(0x7FFFFFFF):
        Q_LE.pack_into(message, 0, nonce)
        if 0 >= cmp(hashlib.sha512(hashlib.sha512(message).digest()).digest(), target_bytes):
            return nonce

def do_pow_vs():
    lib = ctypes.CDLL('bin\\bmpow{0}.dll'.format(interpreter_bits))

    lib.BitmessagePOW.argtypes = [ctypes.c_char_p, ctypes.c_uint64]
    lib.BitmessagePOW.restype = ctypes.c_uint64

    return lib.BitmessagePOW(digest, target)

def do_pow_mingw():
    lib = ctypes.CDLL('bmpow{0}_m.dll'.foramt(interpreter_bits))

    lib.BitmessagePOW.argtypes = [ctypes.c_char_p, ctypes.c_uint64]
    lib.BitmessagePOW.restype = ctypes.c_uint64

    return lib.BitmessagePOW(digest, target)

def do_pow_alt():
    lib = ctypes.CDLL('bitmsghash{0}.dll'.format(interpreter_bits))

    lib.BitmessagePOW.argtypes = [ctypes.c_char_p, ctypes.c_uint64]
    lib.BitmessagePOW.restype = ctypes.c_uint64

    return lib.BitmessagePOW(digest, target)


for do_pow in [do_pow_py_be, do_pow_py_le, do_pow_vs, do_pow_mingw, do_pow_alt]:
    try:
        start = timeit.default_timer()
        nonce = do_pow()
        elapsed = timeit.default_timer() - start
        rate = nonce / elapsed if elapsed > 0 else nonce
        logger.info('%s returned %#018x in %.6f seconds (~%d nonces / second)', do_pow.__name__, nonce, elapsed, rate)
    except Exception as err:
        logger.warning('%s failed: %s', do_pow.__name__, err)
