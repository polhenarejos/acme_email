# -*- coding: utf-8 -*-
"""
Created on Thu Nov 11 19:24:35 2021

@author: Pol
"""

import dkim
from . import exception

class DKIM(exception.Error):
    def __init__(self, message):
        super().__init__(message)

class VerificationFailed(DKIM):
    def __init__(self):
        super().__init__('DKIM-Signature does not pass the verification')

class BadSignatureHeader(DKIM):
    def __init__(self):
        super().__init__('Bad DKIM-Signature header')

class MissingTags(DKIM):
    def __init__(self):
        super().__init__('Missing h fields in DKIM-Signature header')

class UnmatchedTagD(DKIM):
    def __init__(self):
        super().__init__('From\'s email domain does not match DKIM d tag')

class SignatureNotFound(DKIM):
    def __init__(self):
        super().__init__('DKIM-Signature not found')

def ProcessDKIM(msg, from_addr):
    dkim_signature = msg.get('DKIM-Signature',None)
    if (not dkim_signature):
        raise SignatureNotFound
    if ('Authentication-Results' not in msg):
        msg['Authentication-Results'] = 'dkim=pass' if dkim.verify(bytes(msg)) else 'dkim=nopass'
    if ('dkim=pass' not in msg['Authentication-Results'].lower()):
        raise VerificationFailed
    dkim_tags = {}
    for d in dkim_signature.split(';'):
        t = d.strip().split('=')
        dkim_tags[t[0]] = t[1]
    if ('h' not in dkim_tags):
        raise BadSignatureHeader
    dkim_h = ['from','auto-submitted','date','message-id','subject','to']
    if not set(dkim_h).issubset(set(dkim_tags['h'].split(':'))):
        raise MissingTags
    if (dkim_tags['d'].lower() != from_addr.split('@')[1]):
        raise UnmatchedTagD
