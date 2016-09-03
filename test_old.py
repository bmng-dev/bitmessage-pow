import argparse
import ctypes
import hashlib
import logging
import struct

logging.basicConfig(format='%(levelname)8s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

Q = struct.Struct('!Q')

payload = '\x00' * 4
time_to_live = 300
trials = 1000
padding = 1000

payload = payload[:2**18]
adjustedLength = len(payload) + padding
digest = hashlib.sha512(payload).digest()
target = 2 ** 64 / (trials * (adjustedLength + ((time_to_live * adjustedLength) / (2 ** 16))))

parser = argparse.ArgumentParser()
parser.add_argument('--win', action='store_true')
args = parser.parse_args()
logger.info(args)
try:
    if args.win:
        lib = ctypes.WinDLL('BitMsgHash32.dll')
    else:
        lib = ctypes.CDLL('BitMsgHash32.dll')

    do_pow = lib.BitmessagePOW
    do_pow.argtypes = [ctypes.c_char_p, ctypes.c_uint64]
    do_pow.restype = ctypes.c_uint64

    logger.info('%.6f', do_pow(digest, target))
except:
    logger.exception('Exception')
