from certbot import util
from certbot import crypto_util
from certbot.compat import os

from OpenSSL import crypto
import re, logging

logger = logging.getLogger(__name__)   

def is_email(domain_name):
    REGEX = r'^[\w\-\.]+@([\w\-]+\.)+[\w\-]{2,4}$'
    return re.fullmatch(REGEX, domain_name)

def make(pkey_pem, emails):
    private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, pkey_pem)
    csr = crypto.X509Req()
    extensions = [
        crypto.X509Extension(
            b'subjectAltName',
            critical=False,
            value=', '.join(('email:' if is_email(e) else 'DNS:') + e for e in emails).encode('utf-8')
        ),
    ]
    csr.add_extensions(extensions)
    csr.set_pubkey(private_key)
    csr.set_version(2)
    csr.get_subject().__setattr__('commonName', emails[0])
    csr.sign(private_key, 'sha256')
    csr_pem = crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr)
    return csr_pem

def init_save_csr(privkey, email, config):
    path = config.csr_dir
    csr_pem = make(privkey.pem, email)
    util.make_or_verify_dir(path, 0o755, config.strict_permissions)
    csr_f, csr_filename = util.unique_file(os.path.join(path, 'csr-certbot.pem'), 0o644, "wb")
    with csr_f:
        csr_f.write(csr_pem)
    logger.debug("Creating CSR: %s", csr_filename)
    return util.CSR(csr_filename, csr_pem, "pem")

def prepare(emails, config, key=None):
    if config.dry_run:
        key = key or util.Key(file=None, pem=crypto_util.make_key(config.rsa_key_size))
        ## CSR is always used, as it MUST send "email" identifier (dns by default)
        #csr = util.CSR(file=None, form="pem", data=make_csr(key.pem, emails))
    else:
        key = key or crypto_util.init_save_key(config.rsa_key_size, config.key_dir)
    csr = init_save_csr(key, emails, config)
    return key,csr
