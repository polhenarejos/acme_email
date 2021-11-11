# -*- coding: utf-8 -*-
"""
Created on Thu Nov 11 19:34:56 2021

@author: Pol
"""

from . import exception

from cryptography.hazmat.primitives.serialization import pkcs7

from cryptography.x509.oid import ExtensionOID
from cryptography import x509

class PKCS7(exception.Error):
    def __init__(self, message):
        super().__init__(message)

class NoSANFound(PKCS7):
    def __init__(self):
        super().__init__('No subjAltNames found in the certificate')

class FromAddrNotInSAN(PKCS7):
    def __init__(self):
        super().__init__('From Address not found in subjAltNames')
        
def ProcessPKCS7(msg, from_addr):
    subjaltnames = None
    for att in msg.iter_attachments():
        if (att.get_content_type() == 'application/pkcs7-signature'):
            certs = pkcs7.load_der_pkcs7_certificates(att.get_content())
            for cert in certs:
                try:
                    ex = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
                except x509.ExtensionNotFound:
                    continue
                if (not ex.value.ca):
                    try:
                        ex = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    except x509.ExtensionNotFound:
                        continue
                    subjaltnames = ex.value.get_values_for_type(x509.RFC822Name)
                    break
    if (not subjaltnames):
        raise NoSANFound
    if (from_addr not in subjaltnames):
        raise FromAddrNotInSAN()