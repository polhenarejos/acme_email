#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Nov 30 17:46:41 2021

@author: Pol
"""

import os
import ssl
import re
from cryptography import x509
import platform
import subprocess

def get_root_ca_certs(linux_certs_dir_path='/etc/ssl/certs'):
    system = platform.system().lower()
    
    #https://stackoverflow.com/a/64445061/4260911
    if system == 'windows':
        items = ssl.enum_certificates("root")
        for cert_bytes, encoding, is_trusted in items:
            if encoding == "x509_asn":
                cert = x509.load_der_x509_certificate(cert_bytes)
                yield cert

    elif system == 'linux':
        certs_file_names = os.listdir(linux_certs_dir_path)
        for cert_file_name in certs_file_names:
            cert_file_path = os.path.join(linux_certs_dir_path, cert_file_name)
            if not os.path.isfile(cert_file_path):
                continue

            with open(cert_file_path, 'rb') as f:
                cert_pem = f.read()
                cert = x509.load_pem_x509_certificate(cert_pem)
                yield cert
                
    elif system == 'darwin':
        keychains = [
              '/Library/Keychains/System.keychain',
              '/System/Library/Keychains/SystemRootCertificates.keychain'
            ]
        proc = subprocess.Popen(['security','find-certificate','-a', '-p']+keychains,stdout=subprocess.PIPE)
        res = proc.stdout.read()
        root_certs = list(filter(lambda a: a!=b'\n' and a!=b'', re.split(b'(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)', res, flags=re.MULTILINE | re.DOTALL)))
        for cert_pem in root_certs:
            cert = x509.load_pem_x509_certificate(cert_pem)
            yield cert

    else:
        raise NotImplemented(f'missing implementation for this operating system="{system}"')

