#!/usr/bin/env python3

import argparse, logging, sys
import zope.component
from certbot._internal.plugins import disco as plugins_disco
from certbot._internal.plugins import selection as plug_sel
from certbot._internal import cli
from certbot._internal import main as certbot_main
from certbot._internal import reporter
from certbot._internal import log
from certbot._internal.display import obj as display_obj
from certbot import errors
from certbot import util
from certbot import configuration
from certbot import interfaces

from certbot_castle import csr as csr_util

logger = logging.getLogger(__name__)   
 
def prepare_cli_args(args):
    cli_args = []
    command = args.command.lower()
    if (args.config_dir): cli_args.extend(['--config-dir',args.config_dir])
    if (args.work_dir): cli_args.extend(['--work-dir',args.work_dir])
    if (args.logs_dir): cli_args.extend(['--logs-dir',args.logs_dir])
    if (command == 'cert'): cli_args.extend(['certonly'])
    else: cli_args.extend([command])
    if (args.dry_run):    
        cli_args.extend(['--dry-run'])
    for email in args.email:
        cli_args.extend(['-d',email])
    return cli_args

def prepare_config(cli_args):    
    plugins = plugins_disco.PluginsRegistry.find_all()
    cargs = cli.prepare_and_parse_args(plugins, cli_args)
    config = configuration.NamespaceConfig(cargs)
    zope.component.provideUtility(config, interfaces.IConfig)
    return config,plugins

def request_cert(args, config):
    key, csr = csr_util.prepare(args.email, config, usage=args.usage)
    ## Reparse for including --csr arguments
    cli_args = prepare_cli_args(args)
    cli_args.extend(['--csr',csr.file])
    if (args.test):
        cli_args.extend(['--server','https://acme-staging.castle.cloud/acme/directory'])
    else:
        cli_args.extend(['--server','https://acme.castle.cloud/acme/directory'])
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
    if (args.non_interactive):    
        cli_args.extend(['-n'])
    config,plugins = prepare_config(cli_args)
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
    certbot_main._report_new_cert(config, cert_path, fullchain_path, key.file)
    if (not config.dry_run):
        certbot_main._install_cert(config, le_client, args.email)
    else:
        util.safely_remove(csr.file)
    
def main(args):
    ## Prepare storage system
    command = args.command.lower()
    log.pre_arg_parse_setup()
    cli_args = prepare_cli_args(args)
    config,_ = prepare_config(cli_args)
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
        
def process_args(args):
    for e in args.email:
        if ('*' in e):
            raise argparse.ArgumentTypeError("Wildcards are not allowed in email addresses")

def parse_args():
    parser = argparse.ArgumentParser(description='Requests a S/MIME certificate')
    parser.add_argument('-e','--email', help='E-mail address to certify. Multiple e-mail addresses are allowed', required=True, action='append')
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

    args = parser.parse_args()
    process_args(args)
    
    return args


if __name__ == "__main__":
    
    args = parse_args()
    main(args)
    