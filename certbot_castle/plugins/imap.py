import logging
import abc

logging.basicConfig(
    format='%(asctime)s - %(levelname)s: %(message)s',
    level=logging.DEBUG
)

import zope.interface

from acme import messages
from certbot import interfaces
from certbot import errors
from certbot.plugins import common

from certbot_castle import challenge

import josepy as jose
import imapclient, imaplib
from smtplib import SMTP, SMTP_SSL
import ssl, email

from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives import hashes  # type: ignore
from cryptography.x509.oid import ExtensionOID
from cryptography import x509

from email.message import EmailMessage
from email import policy

logger = logging.getLogger(__name__)

class Authenticator(common.Plugin, interfaces.Authenticator, metaclass=abc.ABCMeta):

    description = "Automatic S/MIME challenge by using IMAP integration"

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)

    @classmethod
    def add_parser_arguments(cls, add):
        add('login',help='IMAP login')
        add('password',help='IMAP password')
        add('host',help='IMAP server host')
        add('port',help='IMAP server port')
        add('ssl',help='IMAP SSL',action='store_true')
        
        add('smtp-method',help='SMTP method {STARTTLS,SSL,plain}',choices= ['STARTTLS','SSL','plain'])
        add('smtp-login',help='IMAP login')
        add('smtp-password',help='IMAP password')
        add('smtp-host',help='IMAP server host')
        add('smtp-port',help='IMAP server port')

    def more_info(self):  # pylint: disable=missing-function-docstring
        return("This authenticator performs an interactive email-reply-00 challenge. "
               "It configures an IMAP and SMTP e-mail clients to receive and answer ACME challenges. ")

    def prepare(self):  # pylint: disable=missing-function-docstring
        self.imap = imapclient.IMAPClient(self.conf('host'), port=self.conf('port'), use_uid=False, ssl=True if self.conf('ssl') else False)
        self.imap.login(self.conf('login'),self.conf('password'))
        self.imap.select_folder('INBOX')
        self.imap.idle()
        
        method = self.conf('smtp-method')
        smtp_server = self.conf('smtp-host') if self.conf('smtp-host') else self.conf('host')
        port = self.conf('smtp-port') if self.conf('smtp-port') else self.conf('port')
        login = self.conf('smtp-login') if self.conf('smtp-login') else self.conf('login')
        password = self.conf('smtp-password') if self.conf('smtp-password') else self.conf('password')
        if (method == 'STARTTLS'):
            context = ssl.create_default_context()
            port = port if port else 587
            self.smtp = SMTP(smtp_server,port=port)
            self.smtp.ehlo()
            self.smtp.starttls(context=context) # Secure the connection
            self.smtp.ehlo() # Can be omitted
        elif (method == 'SSL'):
            context = ssl.create_default_context()
            port = port if port else 465
            self.smtp = SMTP_SSL(smtp_server,port=port,context=context)
        else:
            port = port if port else 25
            self.smtp = SMTP(smtp_server,port=port)
        self.smtp.login(login,password)

    def get_chall_pref(self, domain):
        # pylint: disable=unused-argument,missing-function-docstring
        return [challenge.EmailReply00]

    def perform(self, achalls):  # pylint: disable=missing-function-docstring
        return [self._perform_emailreply00(achall) for achall in achalls]

    def _perform_emailreply00(self, achall):
        response, _ = achall.challb.response_and_validation(achall.account_key)
        
        notify = zope.component.getUtility(interfaces.IDisplay).notification

        text = 'A challenge request for S/MIME certificate has been sent. In few minutes, ACME server will send a challenge e-mail to requested recipient. You do not need to take ANY action, as it will be replied automatically.'
        notify(text,pause=False)
        stop = False
        dkim_h = ['from','auto-submitted','date','message-id','subject','to']
        for i in range(30):
            idle = self.imap.idle_check(timeout=10)
            for msg in idle:
                uid, state = msg
                if state == b'EXISTS':
                    self.imap.idle_done()
                    respo = self.imap.fetch(uid, ['RFC822'])
                    for message_id, data in respo.items():
                        if (b'RFC822' in data):
                            msg = email.message_from_bytes(data[b'RFC822'],_class=EmailMessage,policy=policy.default)
                            if (email.utils.parseaddr(msg['From'])[1] != achall.challb.chall.from_addr):
                                continue
                            if (msg['To'] != achall.domain):
                                continue
                            subject = msg['Subject']
                            dkim = msg.get('DKIM-Signature',None)
                            from_addr = email.utils.parseaddr(msg['From'])[1]
                            if (dkim):
                                if ('Authentication-Results' not in msg):
                                    raise errors.AuthorizationError('DKIM signature is used but your email provider does not insert "Authentication-Results" header')
                                if ('dkim=pass' not in msg['Authentication-Results'].lower()):
                                    raise errors.AuthorizationError('DKIM signature is used but it does not pass the verification')
                                dkim_tags = {}
                                for d in dkim.split(';'):
                                    t = d.strip().split('=')
                                    dkim_tags[t[0]] = t[1]
                                if ('h' not in dkim_tags):
                                    raise errors.AuthorizationError('Bad DKIM signature header')
                                if not set(dkim_h).issubset(set(dkim_tags['h'].split(':'))):
                                    raise errors.AuthorizationError('Missing h fields in DKIM-Signature header')
                                if (dkim_tags['d'].lower() != from_addr.split('@')[1]):
                                    raise errors.AuthorizationError('From\'s email domain does not match DKIM d tag')
                            elif (msg.get_content_subtype() == 'signed'):
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
                                    raise errors.AuthorizationError('S/MIME signature is used but no subjAltNames were found in its certificate')
                                if (from_addr not in subjaltnames):
                                    raise errors.AuthorizationError('S/MIME signature is used but no From is not in subjAltNames')
                            if (subject.startswith('ACME: ')):
                                
                                token64 = subject.split(' ')[-1]
                                token1 = jose.b64.b64decode(token64)
                                full_token = token1+achall.chall.token

                                # We reconstruct the ChallengeBody
                                challt = messages.ChallengeBody.from_json({ 'type': 'email-reply-00', 'token': jose.b64.b64encode(bytes(full_token)).decode('ascii'), 'url': achall.challb.uri, 'status': achall.challb.status.to_json(), 'from': achall.challb.chall.from_addr })
                                response, validation = challt.response_and_validation(achall.account_key)
                                if ('Reply-To' in msg):
                                    to = msg['Reply-To']
                                else:
                                    to = msg['From']
                                me = msg['To']
                                message = 'From: {}\n'.format(me)
                                message += 'To: {}\n'.format(to)
                                message += 'In-Reply-To: {}\n'.format(msg['Message-ID'])
                                message += 'Subject: Re: {}\n\n'.format(subject)
                                digest = hashes.Hash(hashes.SHA256())
                                digest.update(validation.encode())
                                thumbprint = jose.b64encode(digest.finalize()).decode()
                                message += '-----BEGIN ACME RESPONSE-----\n{}\n-----END ACME RESPONSE-----\n'.format(thumbprint)
                                self.smtp.sendmail(me,to,message)
                                
                                self.imap.add_flags(message_id,imapclient.SEEN)
                                self.imap.add_flags(message_id,imapclient.DELETED)
                                notify('The ACME response has been sent successfully!',pause=False)
                                stop = True
            if (stop):
                break
        return response

    def cleanup(self, achalls):  # pylint: disable=missing-function-docstring
        #self.imap.idle_done()
        try:
            self.imap.logout()
        except imaplib.IMAP4.abort:
            pass
        self.smtp.quit()
