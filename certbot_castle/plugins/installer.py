import logging

import zope.interface

from certbot import interfaces
from certbot import util
from certbot import errors
from certbot.plugins import common
from certbot.compat import os

from OpenSSL import crypto

logger = logging.getLogger(__name__)

@zope.interface.implementer(interfaces.IInstaller)
@zope.interface.provider(interfaces.IPluginFactory)
class Installer(common.Plugin):
    
    description = "Generates PKCS12 container from S/MIME challenge"
    
    @classmethod
    def add_parser_arguments(cls, add):
        
        add('no-passphrase',help='Installs the PKCS12 without passphrase. Use with CAUTION: the PKCS12 file contains the private key',action='store_true')

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
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(cert_path,'rb').read())
        logger.debug('Loading key ')
        privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, open(key_path,'rb').read())
        logger.debug('Loading chain ')
        chain = crypto.load_certificate(crypto.FILETYPE_PEM, open(fullchain_path,'rb').read())
        pfx = crypto.PKCS12()
        pfx.set_privatekey(privkey)
        pfx.set_certificate(cert)
        pfx.set_ca_certificates([chain])
        pfx.set_friendlyname(domain.encode('utf-8'))
        notify = zope.component.getUtility(interfaces.IDisplay).notification
        if (not self.conf('no-passphrase')):
            text = 'A passphrase is needed for protecting the PKCS12 container. '
            notify(text,pause=False)
            input = zope.component.getUtility(interfaces.IDisplay).input
            code,pf = input('Enter passphrase: ', force_interactive=True)
            code,vpf = input('Re-enter passphrase: ', force_interactive=True)
            while (pf != vpf):
                notify('Passphrases do not match.',pause=False)
                code, vpf = input('Re-enter passphrase: ', force_interactive=True)
        else:
            pf = ''
        pfxdata = pfx.export(pf.encode('ascii'))
        path, _ = os.path.split(cert_path)
        pfx_f, pfx_filename = util.unique_file(os.path.join(path, 'cert-certbot.pfx'), 0o600, "wb")
        with pfx_f:
            pfx_f.write(pfxdata)
        notify('PKCS12 container generated at '+pfx_filename)

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