#!/usr/bin/env python3

import argparse, logging, re
import zope.component
from certbot._internal.plugins import disco as plugins_disco
from certbot._internal.plugins import selection as plug_sel
from certbot._internal import cli
from certbot._internal import configuration
from certbot._internal import main as certbot_main
from certbot._internal import reporter
from certbot._internal import log
from certbot import errors
from certbot import crypto_util
from certbot import util
from certbot.compat import os

from OpenSSL import crypto

logger = logging.getLogger(__name__)   
 
def is_email(domain_name):
    REGEX = r'^[\w\-\.]+@([\w\-]+\.)+[\w\-]{2,4}$'
    return re.fullmatch(REGEX, domain_name)

def init_save_csr(privkey, email, config):
    path = config.csr_dir
    csr_pem = make_csr(privkey.pem, email)
    util.make_or_verify_dir(path, 0o755, config.strict_permissions)
    csr_f, csr_filename = util.unique_file(os.path.join(path, 'csr-certbot.pem'), 0o644, "wb")
    with csr_f:
        csr_f.write(csr_pem)
    logger.debug("Creating CSR: %s", csr_filename)
    return util.CSR(csr_filename, csr_pem, "pem")

def make_csr(pkey_pem, emails):
    private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, pkey_pem)
    csr = crypto.X509Req()
    extensions = [
        crypto.X509Extension(
            b'subjectAltName',
            critical=False,
            value=', '.join(('email:' if is_email(e) else 'DNS:') + e for e in emails).encode('ascii')
        ),
    ]
    csr.add_extensions(extensions)
    csr.set_pubkey(private_key)
    csr.set_version(2)
    csr.get_subject().__setattr__('commonName', emails[0])
    csr.sign(private_key, 'sha256')
    csr_pem = crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr)
    return csr_pem

def prepare_csr(emails, config, key=None):
    if config.dry_run:
        key = key or util.Key(file=None, pem=crypto_util.make_key(config.rsa_key_size))
        csr = util.CSR(file=None, form="pem", data=make_csr(key.pem, emails))
    else:
        key = key or crypto_util.init_save_key(config.rsa_key_size, config.key_dir)
        csr = init_save_csr(key, emails, config)
    return key,csr

def prepare_cli_args(args):
    cli_args = []
    command = args.command.lower()
    if (args.config_dir): cli_args.extend(['--config-dir',args.config_dir])
    if (args.work_dir): cli_args.extend(['--work-dir',args.work_dir])
    if (args.logs_dir): cli_args.extend(['--logs-dir',args.logs_dir])
    for email in args.email:
        cli_args.extend(['-d',email])
    if (command == 'cert'): cli_args.extend(['certonly'])
    else: cli_args.extend([command])
    return cli_args

def prepare_config(cli_args):    
    plugins = plugins_disco.PluginsRegistry.find_all()
    cargs = cli.prepare_and_parse_args(plugins, cli_args)
    config = configuration.NamespaceConfig(cargs)
    zope.component.provideUtility(config)
    return config,plugins

def request_cert(args, config):
    key, csr = prepare_csr(args.email, config)
    #certbot certonly --config-dir . --work-dir . --logs-dir . --server https://acme.castle.cloud/acme/directory --csr csr/test.pem -a castle-interactive -d trocotronic@redyc.com
    ## Reparse for including --csr arguments
    cli_args = prepare_cli_args(args)
    cli_args.extend(['--csr',csr.file])
    cli_args.extend(['--server','https://acme.castle.cloud/acme/directory'])
    cli_args.extend(['-a','castle-interactive'])
    cli_args.extend(['-i','castle-installer'])
    cli_args.extend(['-m',args.contact])
    if (args.agree_tos):    
        cli_args.extend(['--agree-tos'])
    if (args.non_interactive):    
        cli_args.extend(['-n'])
    if (args.dry_run):    
        cli_args.extend(['--dry-run'])
    config,plugins = prepare_config(cli_args)
    config.key_path = key.file
    try:
        # installers are used in auth mode to determine domain names
        installer, auth = plug_sel.choose_configurator_plugins(config, plugins, "certonly")
    except errors.PluginSelectionError as e:
        logger.info("Could not choose appropriate plugin: %s", e)
        raise
    le_client = certbot_main._init_le_client(config, auth, installer)

    cert_path, fullchain_path = certbot_main._csr_get_and_save_cert(config, le_client)
    config.cert_path = cert_path
    config.fullchain_path = fullchain_path
    certbot_main._report_new_cert(config, cert_path, fullchain_path)
    certbot_main._install_cert(config, le_client, args.email)
    
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
    certbot_main.set_displayer(config)
    report = reporter.Reporter(config)
    zope.component.provideUtility(report)
    util.atexit_register(report.print_messages)

    if (command == 'cert'):
        request_cert(args, config)
        
def process_args(args):
    if (len(args.email) > 1):
        raise argparse.ArgumentTypeError("Multiple e-mails are not allowed")

def parse_args():
    parser = argparse.ArgumentParser(description='Requests a S/MIME certificate')
    parser.add_argument('-e','--email', help='E-mail of the issued certificate', required=True, action='append')
    parser.add_argument('-t','--test', help='Tests the certification from a staging server', action='store_true')
    parser.add_argument('--dry-run', help='Do not store any file. For testing', action='store_true')
    parser.add_argument('-n','--non-interactive', help='Runs the certification without any user interaction', action='store_true')
    parser.add_argument('-c','--config-dir', help='Configuration directory')
    parser.add_argument('-w','--work-dir', help='Working directory')
    parser.add_argument('-l','--logs-dir', help='Logs directory')
    parser.add_argument('--agree-tos', help='Logs directory')
    parser.add_argument('--contact', help='Contact e-mail for important account notifications')
    parser.add_argument('command',choices=['cert','revoke','renew'])
    args = parser.parse_args()
    process_args(args)
    
    return args


if __name__ == "__main__":
    
    args = parse_args()
    main(args)
    