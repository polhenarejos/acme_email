#!/usr/bin/env python3

import argparse, logging, sys, getpass, tempfile, os
import zope.component
from certbot._internal.plugins import disco as plugins_disco
from certbot._internal.plugins import selection as plug_sel
from certbot._internal import cli
from certbot._internal import main as certbot_main
from certbot._internal import reporter
from certbot._internal import log
from certbot._internal.display import obj as display_obj
from certbot.display import util as display_util
from certbot import errors
from certbot import util
from certbot import configuration
from certbot import interfaces
from certbot.compat import misc

from certbot_castle import csr as csr_util
from certbot_castle.utils import get_root_ca_certs

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding

logger = logging.getLogger(__name__)   
 
def prepare_cli_args(args):
    cli_args = []
    command = args.command.lower()
    if (args.config_dir): cli_args.extend(['--config-dir',args.config_dir])
    if (args.work_dir): cli_args.extend(['--work-dir',args.work_dir])
    if (args.logs_dir): cli_args.extend(['--logs-dir',args.logs_dir])
    
    if (command == 'cert'): cli_args.extend(['certonly'])
    else: cli_args.extend([command])
    
    if (args.test): cli_args.extend(['--server','https://acme-staging.castle.cloud/acme/directory'])
    else: cli_args.extend(['--server','https://acme.castle.cloud/acme/directory'])
    
    if (args.non_interactive): cli_args.extend(['-n'])
        
    return cli_args

def prepare_config(cli_args):    
    plugins = plugins_disco.PluginsRegistry.find_all()
    cargs = cli.prepare_and_parse_args(plugins, cli_args)
    config = configuration.NamespaceConfig(cargs)
    zope.component.provideUtility(config, interfaces.IConfig)
    return config,plugins

def root_cert_advise():
    root_certs = get_root_ca_certs()
    castle_fingerprints = [
        '1845b9560b38a0ac11494f4cf2b2f372a1a398e11439066ca2734ecc86d67c0e',
        '92966a8d8fbc35cafa320fcf32f805dc7be483e95615df258b8d38eace0cfbb9',
    ]
    fingerprints = list(map(lambda a: a.fingerprint(hashes.SHA256()).hex(), root_certs))
    matches = sum(e in fingerprints for e in castle_fingerprints)
    if (matches == 0):
        text = 'You are requesting a S/MIME certificate to CASTLE ACME server. Remember to add the root certificate into your trust store for proper operation.'
        display_util.notification(text,pause=False)

def request_cert(args, config):
    root_cert_advise()
    key, csr = csr_util.prepare(args.email, config, key_path=args.key_path, usage=args.usage)
    ## Reparse for including --csr arguments
    cli_args = prepare_cli_args(args)
    if (args.dry_run):    
        cli_args.extend(['--dry-run'])
    for email in args.email:
        cli_args.extend(['-d',email])
    cli_args.extend(['--csr',csr.file])
    if (args.imap):
        cli_args.extend(['-a','castle-imap'])
        cli_args.extend(['--castle-imap-login',args.login])
        cli_args.extend(['--castle-imap-password',args.password])
        cli_args.extend(['--castle-imap-host',args.host])
        if (args.port):
            cli_args.extend(['--castle-imap-port',args.port])
        if (args.ssl):
            cli_args.extend(['--castle-imap-ssl'])
        if (args.smtp_method):
            cli_args.extend(['--castle-imap-smtp-method',args.smtp_method])
        if (args.smtp_login):
            cli_args.extend(['--castle-imap-smtp-login',args.smtp_login])
        if (args.smtp_password):
            cli_args.extend(['--castle-imap-smtp-password',args.smtp_password])
        cli_args.extend(['--castle-imap-smtp-host',args.smtp_host])
        if (args.smtp_port):
            cli_args.extend(['--castle-imap-smtp-port',args.smtp_port])
    elif (args.outlook):
        cli_args.extend(['-a','castle-mapi'])
        cli_args.extend(['--castle-mapi-account',args.outlook_account])
    elif (args.tb):
        cli_args.extend(['-a','castle-tb'])
        if (args.tb_profile):
            cli_args.extend(['--castle-tb-profile',args.tb_profile])
        if (args.tb_unsafe):
            cli_args.extend(['--castle-tb-unsafe'])
        if (args.tb_bin):
            cli_args.extend(['--castle-tb-bin',args.tb_bin])
    else:
        cli_args.extend(['-a','castle-interactive'])
    cli_args.extend(['-i','castle-installer'])
    if (args.no_passphrase):
        cli_args.extend(['--castle-installer-no-passphrase'])
    elif (args.passphrase):
        cli_args.extend(['--castle-installer-passphrase',args.passphrase])
    cli_args.extend(['-m',args.contact])
    if (args.agree_tos):    
        cli_args.extend(['--agree-tos'])
    config,plugins = prepare_config(cli_args)
    
    config.cert_path = config.live_dir+'/cert.pem'
    config.chain_path = config.live_dir+'/ca.pem'
    config.fullchain_path = config.live_dir+'/chain.pem'
    
    config.key_path = key.file
    try:
        # installers are used in auth mode to determine domain names
        installer, auth = plug_sel.choose_configurator_plugins(config, plugins, "certonly")
    except errors.PluginSelectionError as e:
        logger.info("Could not choose appropriate plugin: %s", e)
        raise
    le_client = certbot_main._init_le_client(config, auth, installer)

    cert_path, chain_path, fullchain_path = certbot_main._csr_get_and_save_cert(config, le_client)
    config.cert_path = cert_path
    config.fullchain_path = fullchain_path
    config.chain_path = chain_path
    certbot_main._csr_report_new_cert(config, cert_path, chain_path, fullchain_path)
    if (not config.dry_run):
        certbot_main._install_cert(config, le_client, args.email)
    else:
        util.safely_remove(csr.file)
        
def try_open_p12(file,passphrase=None):
    with open(args.cert_path,'rb') as p12:
        (private_key, certificate, _) = pkcs12.load_key_and_certificates(p12.read(),passphrase)
        temp_cert = tempfile.NamedTemporaryFile(delete=False)
        temp_cert.write(certificate.public_bytes(Encoding.PEM))
        temp_cert.close()
        temp_pkey = tempfile.NamedTemporaryFile(delete=False)
        temp_pkey.write(private_key.private_bytes(encoding=Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption()))
        temp_pkey.close()
        return temp_pkey.name,temp_cert.name
    return None,None
         
def revoke_cert(args, config):
    cli_args = prepare_cli_args(args)
    if (args.reason):
        cli_args.extend(['--reason',args.reason])
    cli_args.extend(['--no-delete-after-revoke'])
    key_path,cert_path = None,None
    try:
        key_path,cert_path = try_open_p12(args.cert_path)
        cli_args.extend(['--cert-path',cert_path])
        cli_args.extend(['--key-path',key_path])
    except ValueError as e: 
        if ('Invalid password' in str(e)):
            passphrase = None
            if (args.passphrase):
                passphrase = args.passphrase.encode('utf-8')
            else:
                text = 'Introduce the passphrase of the PKCS12 file.'
                display_util.notification(text,pause=False)
                pf = getpass.getpass('Enter passphrase: ')
                passphrase = pf.encode('utf-8')
            try:
                key_path,cert_path = try_open_p12(args.cert_path,passphrase=passphrase)
                cli_args.extend(['--cert-path',cert_path])
                cli_args.extend(['--key-path',key_path])
            except ValueError as e:
                if ('Invalid password' in str(e)):
                    raise e
        elif ('Could not deserialize'): #pem
            if (args.cert_path):
                cli_args.extend(['--cert-path',args.cert_path])
            if (args.key_path):
                cli_args.extend(['--key-path',args.key_path])
    config,plugins = prepare_config(cli_args)
    certbot_main.revoke(config,plugins)
    if (key_path):
        os.unlink(key_path)
    if (cert_path):
        os.unlink(cert_path)
    
def main(args):
    ## Prepare storage system
    command = args.command.lower()
    log.pre_arg_parse_setup()
    cli_args = prepare_cli_args(args)
    config,_ = prepare_config(cli_args)
    misc.raise_for_non_administrative_windows_rights()

    try:
        log.post_arg_parse_setup(config)
        certbot_main.make_or_verify_needed_dirs(config)
    except errors.Error:
        raise
    report = reporter.Reporter(config)
    zope.component.provideUtility(report, interfaces.IReporter)
    util.atexit_register(report.print_messages)
    with certbot_main.make_displayer(config) as displayer:
        display_obj.set_display(displayer)

    if (command == 'cert'):
        request_cert(args, config)
    elif (command == 'revoke'):
        revoke_cert(args, config)
        
def process_args(args):
    if args.email:
        for e in args.email:
            if ('*' in e):
                raise argparse.ArgumentTypeError("Wildcards are not allowed in email addresses")

def parse_args():
    parser = argparse.ArgumentParser(description='Requests a S/MIME certificate')
    parser.add_argument('-e','--email', help='E-mail address to certify. Multiple e-mail addresses are allowed', required='cert' in sys.argv, action='append')
    parser.add_argument('-t','--test', help='Tests the certification from a staging server', action='store_true')
    parser.add_argument('--dry-run', help='Do not store any file. For testing', action='store_true')
    parser.add_argument('-n','--non-interactive', help='Runs the certification without any user interaction', action='store_true')
    parser.add_argument('-c','--config-dir', help='Configuration directory')
    parser.add_argument('-w','--work-dir', help='Working directory')
    parser.add_argument('-l','--logs-dir', help='Logs directory')
    parser.add_argument('--agree-tos', help='Accepts Terms of Service', action='store_true')
    parser.add_argument('--contact', help='Contact e-mail for important account notifications')
    parser.add_argument('--imap', help='Uses IMAP Authenticator for automatic reply', action='store_true')
    parser.add_argument('command',choices=['cert','revoke','renew'])
    
    parser.add_argument('--login',help='IMAP login',required='--imap' in sys.argv)
    parser.add_argument('--password',help='IMAP password',required='--imap' in sys.argv)
    parser.add_argument('--host',help='IMAP server host',required='--imap' in sys.argv)
    parser.add_argument('--port',help='IMAP server port. If empty, it will be auto-detected')
    parser.add_argument('--ssl',help='IMAP SSL connection',action='store_true')
    
    parser.add_argument('--smtp-method',help='SMTP method {STARTTLS,SSL,plain}',choices= ['STARTTLS','SSL','plain'])
    parser.add_argument('--smtp-login',help='SMTP login. If empty, IMAP login will be used')
    parser.add_argument('--smtp-password',help='SMTP password. If empty, IMAP password will be used')
    parser.add_argument('--smtp-host',help='SMTP server host',required='--imap' in sys.argv)
    parser.add_argument('--smtp-port',help='SMTP server port. If empty, it will be auto-detected')
    
    parser.add_argument('--no-passphrase',help='PKCS12 is stored without passphrase. Use with CAUTION: the PKCS12 contains the private key',action='store_true')
    parser.add_argument('--passphrase',help='Passphrase to use for the PKCS12 generation. This passpharse will be used for private key encryption')
    
    parser.add_argument('--usage', help='Key usage for certificate. Multiple usages can be specified', choices=['digitalSignature','contentCommitment','keyEncipherment','keyAgreement'], action='append')

    parser.add_argument('--cert-path',help='Path where certificate is located',required='revoke' in sys.argv)
    parser.add_argument('--reason',help='Reason of revocation',choices=['unspecified','keycompromise','affiliationchanged','superseded','cessationofoperation'])
    parser.add_argument('--key-path',help='Path of private key location')
    
    parser.add_argument('--outlook', help='Uses MAPI (Outlook) Authenticator for automatic reply', action='store_true')
    parser.add_argument('--outlook-account', help='Outlook account where the challenge is processed', required='--outlook' in sys.argv)

    parser.add_argument('--tb', help='Uses Thunderbird Authenticator for automatic reply', action='store_true')
    parser.add_argument('--tb-unsafe', help='Run authenticator disabling security checks. USE WITH CAUTION.', action='store_true')
    parser.add_argument('--tb-profile', help='Thunderbird profile where it runs')
    parser.add_argument('--tb-bin', help='Thunderbird binary/executable path')

    args = parser.parse_args()
    process_args(args)
    
    return args


if __name__ == "__main__":
    
    args = parse_args()
    main(args)
    