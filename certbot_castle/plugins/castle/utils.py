# -*- coding: utf-8 -*-
"""
Created on Thu Nov 11 19:12:12 2021

@author: Pol
"""

import email
from . import dkim
from . import pkcs7
from . import exception

from acme import messages
from certbot import errors

from cryptography.hazmat.primitives import hashes 

import josepy as jose

class FromAddressMismatch(exception.Error):
    def __init__(self):
        super().__init__('Email From Address does not match with challenge From Address')
                
class ReceiptAddressMismatch(exception.Error):
    def __init__(self):
        super().__init__('Email Receipt Address does not match with challenge email identifier')
        
class BadSubject(exception.Error):
    def __init__(self):
        super().__init__('Subject malformed')

def ProcessEmailChallenge(msg, achall):
    if (email.utils.parseaddr(msg['From'])[1] != achall.challb.chall.from_addr):
        raise FromAddressMismatch
    if (msg['To'] != achall.domain):
        raise ReceiptAddressMismatch
    subject = msg['Subject']
    from_addr = email.utils.parseaddr(msg['From'])[1]

    if (msg.get('DKIM-Signature',None)):
        dkim.ProcessDKIM(msg, from_addr)
    elif (msg.get_content_subtype() == 'signed'):
        pkcs7.ProcessPKCS7(msg, from_addr)
    if (not subject.startswith('ACME: ')):
        raise BadSubject
    token64 = subject.split(' ')[-1]
    token1 = jose.b64.b64decode(token64)
    full_token = token1+achall.chall.token

    # We reconstruct the ChallengeBody
    challt = messages.ChallengeBody.from_json({ 'type': 'email-reply-00', 'token': jose.b64.b64encode(bytes(full_token)).decode('ascii'), 'url': achall.challb.uri, 'status': achall.challb.status.to_json(), 'from': achall.challb.chall.from_addr })
    response, validation = challt.response_and_validation(achall.account_key)
    
    digest = hashes.Hash(hashes.SHA256())
    digest.update(validation.encode())
    thumbprint = jose.b64encode(digest.finalize()).decode()
    return response,'-----BEGIN ACME RESPONSE-----\n{}\n-----END ACME RESPONSE-----\n'.format(thumbprint)
        