import ctypes
import hashlib
import logging
import sys

logging.basicConfig(format='%(levelname)8s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

if sys.maxsize > 2**32:
    logger.info('Python 64-bit')
else:
    logger.info('Python 32-bit')

payload = '\x00'
time_to_live = 300
trials = 1000
padding = 1000

payload = payload[:2**18]
adjustedLength = len(payload) + padding
digest = hashlib.sha512(payload).digest()
target = 2 ** 64 / (trials * (adjustedLength + ((time_to_live * adjustedLength) / (2 ** 16))))

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

for do_pow in [do_pow_x86, do_pow_x64]:
    try:
        logger.info('%s returned %x', do_pow.__name__, do_pow())
    except Exception as err:
        logger.warning('%s failed: %s', do_pow.__name__, err)
