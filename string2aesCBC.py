#!/usr/bin/env python

"""
Copyright (c) 2006-2022 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import os
import random
import string
import hashlib

import base64
from Crypto import Random
import Crypto
from Crypto.Cipher import AES

from lib.core.common import singleTimeWarnMessage
from lib.core.compat import xrange
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW


secret_key = "1234567890abcdefghijklmnopqrstuv".encode("utf-8")
iv = "1234567890abcdef".encode("utf-8")
def hex_to_str(b):
     
  s = ''
  for i in b:
    s += '{0:0>2}'.format(str(hex(i))[2:])
  return(s)
class AESCipher(object):
    
    def __init__(self, key): 
        self.bs = AES.block_size
        self.key = key
    def encrypt(self, raw):
        raw = self._pad(raw)
        #iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC,iv )
        
        return hex_to_str(cipher.encrypt(raw.encode()))
        #return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

myAes = AESCipher(secret_key)

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.MYSQL))

def tamper(payload, **kwargs):
    """
    Replaces (MySQL) instances of space character (' ') with a pound character ('#') followed by a random string and a new line ('\n')

    Requirement:
        * MySQL

    Tested against:
        * MySQL 4.0, 5.0

    Notes:
        * Useful to bypass several web application firewalls
        * Used during the ModSecurity SQL injection challenge,
          http://modsecurity.org/demo/challenge.html

    >>> random.seed(0)
    >>> tamper('1 AND 9227=9227')
    '1%23upgPydUzKpMX%0AAND%23RcDKhIr%0A9227=9227'
    """

    retVal = ""

    if payload:
        retVal=myAes.encrypt(payload)
    return retVal
