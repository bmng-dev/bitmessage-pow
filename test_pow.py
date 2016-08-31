import ctypes
import hashlib
import logging
import struct
import sys
import timeit

logging.basicConfig(format='%(levelname)8s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

Q = struct.Struct('!Q')

if sys.maxsize > 2**32:
    logger.info('Python 64-bit')
else:
    logger.info('Python 32-bit')

logger.info('Pointer Size: %i, Max Size: %#018x', ctypes.sizeof(ctypes.c_void_p), sys.maxsize)

payload = '\x00'
time_to_live = 300
trials = 1000
padding = 1000

payload = payload[:2**18]
adjustedLength = len(payload) + padding
digest = hashlib.sha512(payload).digest()
target = 2 ** 64 / (trials * (adjustedLength + ((time_to_live * adjustedLength) / (2 ** 16))))

def do_pow_py():
    target = Q.pack(target)
    message = bytearray(8 + len(digest))
    message[8:] = digest
    for nonce in xrange(0x7FFFFFFF):
        Q.pack_into(message, 0, nonce)
        if 0 >= cmp(hashlib.sha512(hashlib.sha512(message).digest()).digest(), target):
            return nonce

def do_pow_x86():
    lib = ctypes.CDLL('bmpow32.dll')

    lib.BitmessagePOW.argtypes = [ctypes.c_char_p, ctypes.c_uint64]
    lib.BitmessagePOW.restype = ctypes.c_uint64

    return lib.BitmessagePOW(digest, target)

def do_pow_x64():
    lib = ctypes.CDLL('bmpow64.dll')

    lib.BitmessagePOW.argtypes = [ctypes.c_char_p, ctypes.c_uint64]
    lib.BitmessagePOW.restype = ctypes.c_uint64

    return lib.BitmessagePOW(digest, target)

for do_pow in [do_pow_py, do_pow_x86, do_pow_x64]:
    try:
        start = timeit.default_timer()
        nonce = do_pow()
        elapsed = timeit.default_timer() - start
        rate = nonce / elapsed if elapsed > 0 else nonce
        logger.info('%s returned %#018x in %.6f seconds (~%d nonces / second)', do_pow.__name__, nonce, elapsed, rate)
    except Exception as err:
        logger.warning('%s failed: %s', do_pow.__name__, err)
