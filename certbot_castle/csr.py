from certbot import util
from certbot import crypto_util
from certbot.compat import os

import re, logging

from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)   

def is_email(domain_name):
    REGEX = r'^[\w\-\.]+@([\w\-]+\.)+[\w\-]{2,4}$'
    return re.fullmatch(REGEX, domain_name)

def make(pkey_pem, emails, usage):
    private_key = serialization.load_pem_private_key(pkey_pem, password=None)
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, emails[0]),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, emails[0]),
        ])
        ).add_extension(
            x509.SubjectAlternativeName(
                [x509.RFC822Name(e) for e in emails] +
                [x509.DNSName(e) for e in emails]
                ),
            critical=False,
        )
    if (usage):
        data_encipherment, key_cert_sign, crl_sign, encipher_only, decipher_only = (False,)*5
        digital_signature = 'digitalSignature' in usage
        content_commitment = 'contentCommitment' in usage
        key_encipherment = 'keyEncipherment' in usage
        key_agreement = 'keyAgreement' in usage
        csr = csr.add_extension(
                x509.KeyUsage(
                    digital_signature=digital_signature, 
                    content_commitment=content_commitment, 
                    key_encipherment=key_encipherment, 
                    data_encipherment=data_encipherment, 
                    key_agreement=key_agreement, 
                    key_cert_sign=key_cert_sign, 
                    crl_sign=crl_sign, 
                    encipher_only=encipher_only, 
                    decipher_only=decipher_only,
                ),
                critical=True,
            )
    csr_pem = csr.sign(private_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
    return csr_pem

def init_save_csr(privkey, email, config, usage):
    path = config.csr_dir
    csr_pem = make(privkey.pem, email, usage)
    util.make_or_verify_dir(path, 0o755, config.strict_permissions)
    csr_f, csr_filename = util.unique_file(os.path.join(path, 'csr-certbot.pem'), 0o644, "wb")
    with csr_f:
        csr_f.write(csr_pem)
    logger.debug("Creating CSR: %s", csr_filename)
    return util.CSR(csr_filename, csr_pem, "pem")

def prepare(emails, config, key=None, usage=None):
    if config.dry_run:
        key = key or util.Key(file=None, pem=crypto_util.make_key(config.rsa_key_size))
        ## CSR is always used, as it MUST send "email" identifier (dns by default)
        #csr = util.CSR(file=None, form="pem", data=make_csr(key.pem, emails))
    else:
        key = key or crypto_util.init_save_key(config.rsa_key_size, config.key_dir)
    csr = init_save_csr(key, emails, config, usage)
    return key,csr
