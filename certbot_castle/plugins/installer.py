import logging
import abc
import getpass

from certbot import interfaces
from certbot import util
from certbot import errors
from certbot.plugins import common
from certbot.compat import os
from certbot.display import util as display_util

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

logger = logging.getLogger(__name__)

class Installer(common.Plugin, interfaces.Installer, metaclass=abc.ABCMeta):
    
    description = "Generates PKCS12 container from S/MIME challenge"
    
    @classmethod
    def add_parser_arguments(cls, add):
        
        add('no-passphrase',help='Installs the PKCS12 without passphrase. Use with CAUTION: the PKCS12 file contains the private key',action='store_true')
        add('passphrase',help='Passphrase to use for the PKCS12 generation. This passpharse will be used for private key encryption')

    def more_info(self):  # pylint: disable=missing-function-docstring
        return("This installer generates the PKCS12/PFX container once the certificate is issued. ")
    
    def get_all_names(self):
        return []

    def prepare(self):
        pass 
    
    def deploy_cert(self, domain, cert_path, key_path, chain_path=None, fullchain_path=None):

        if not fullchain_path:
            raise errors.PluginError("CASTLE Installer plugin requires --fullchain-path to generate a PKCS12 container.")
        logger.info("Generating PKCS12 container")
        logger.debug('Loading cert ')
        cert = x509.load_pem_x509_certificate(open(cert_path,'rb').read())
        logger.debug('Loading key ')
        privkey = serialization.load_pem_private_key(open(key_path,'rb').read(), password=None)
        logger.debug('Loading chain ')
        chain = x509.load_pem_x509_certificate(open(chain_path,'rb').read())
        passphrase = None
        if (not self.conf('no-passphrase')):
            if (self.conf('passphrase')):
                passphrase = self.conf('passphrase').encode('utf-8')
            else:
                text = 'A passphrase is needed for protecting the PKCS12 container. '
                display_util.notification(text,pause=False)
                pf = getpass.getpass('Enter passphrase: ')
                vpf = getpass.getpass('Re-enter passphrase: ')
                while (pf != vpf):
                    display_util.notify('Passphrases do not match.')
                    vpf = getpass.getpass('Re-enter passphrase: ')
                passphrase = pf.encode('utf-8')
        algo = serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
        pfxdata = pkcs12.serialize_key_and_certificates(name=domain.encode('utf-8'), key=privkey, cert=cert, cas=[chain], encryption_algorithm=algo)
        path, _ = os.path.split(cert_path)
        pfx_f, pfx_filename = util.unique_file(os.path.join(path, 'cert.pfx'), 0o600, "wb")
        with pfx_f:
            pfx_f.write(pfxdata)
        display_util.notification('PKCS12 container generated at '+pfx_filename,pause=False)

    def enhance(self, domain, enhancement, options=None):
        pass  # pragma: no cover

    def supported_enhancements(self):
        return []

    def get_all_certs_keys(self):
        return []

    def save(self, title=None, temporary=False):
        pass  # pragma: no cover

    def rollback_checkpoints(self, rollback=1):
        pass  # pragma: no cover

    def recovery_routine(self):
        pass  # pragma: no cover

    def view_config_changes(self):
        pass  # pragma: no cover

    def config_test(self):
        pass  # pragma: no cover

    def restart(self):
        pass