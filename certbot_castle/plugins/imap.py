import logging
import abc

logging.basicConfig(
    format='%(asctime)s - %(levelname)s: %(message)s',
    level=logging.DEBUG
)

from certbot import interfaces
from certbot import errors
from certbot.plugins import common
from certbot.display import util as display_util

from certbot_castle import challenge

import imapclient, imaplib
from smtplib import SMTP, SMTP_SSL, SMTPServerDisconnected
import ssl, email


from email.message import EmailMessage
from email import policy

from . import castle

logger = logging.getLogger(__name__)

class Authenticator(common.Plugin, interfaces.Authenticator, metaclass=abc.ABCMeta):

    description = "Automatic S/MIME challenge by using IMAP integration"
    __in_idle = False

    def __set_idle(self, mode):
        if (mode == True and self.__in_idle == False):
            self.imap.idle()
            self.__in_idle = True
        elif (mode == False and self.__in_idle == True):
            self.imap.idle_done()
            self.__in_idle = False

    def _connect_imap(self, context):
        self.imap = imapclient.IMAPClient(
            self.conf('host'),
            port=self.conf('port'),
            use_uid=False,
            ssl=True if self.conf('ssl') else False,
            ssl_context=context
        )
        self.imap.login(self.conf('login'), self.conf('password'))
        self.imap.select_folder('INBOX')
        if b'IDLE' not in self.imap.capabilities():
            raise errors.AuthorizationError('IMAP server does not support IDLE. Cannot continue.')
        self.__idle(True)

    def _connect_smtp(self, context):
        method = self.conf('smtp-method')
        smtp_server = self.conf('smtp-host') if self.conf('smtp-host') else self.conf('host')
        port = self.conf('smtp-port') if self.conf('smtp-port') else self.conf('port')
        login = self.conf('smtp-login') if self.conf('smtp-login') else self.conf('login')
        password = self.conf('smtp-password') if self.conf('smtp-password') else self.conf('password')
        if (method == 'STARTTLS'):
            port = port if port else 587
            self.smtp = SMTP(smtp_server,port=port)
            self.smtp.ehlo()
            self.smtp.starttls(context=context) # Secure the connection
            self.smtp.ehlo() # Can be omitted
        elif (method == 'SSL'):
            port = port if port else 465
            self.smtp = SMTP_SSL(smtp_server,port=port,context=context)
        else:
            port = port if port else 25
            self.smtp = SMTP(smtp_server,port=port)
        self.smtp.login(login,password)

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.__in_idle = False

    @classmethod
    def add_parser_arguments(cls, add):
        add('login',help='IMAP login')
        add('password',help='IMAP password')
        add('host',help='IMAP server host')
        add('port',help='IMAP server port')
        add('ssl',help='IMAP SSL',action='store_true')
        add('no-verify-ssl',help='skip the SSL/TLS certificate verification',action='store_true')

        add('smtp-method',help='SMTP method {STARTTLS,SSL,plain}',choices= ['STARTTLS','SSL','plain'])
        add('smtp-login',help='IMAP login')
        add('smtp-password',help='IMAP password')
        add('smtp-host',help='IMAP server host')
        add('smtp-port',help='IMAP server port')

    def more_info(self):  # pylint: disable=missing-function-docstring
        return("This authenticator performs an interactive email-reply-00 challenge. "
               "It configures an IMAP and SMTP e-mail clients to receive and answer ACME challenges. ")

    def prepare(self):  # pylint: disable=missing-function-docstring
        context = ssl.create_default_context()
        if self.conf('no_verify_ssl'):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self._imap_ssl_context = context
        self._connect_imap(context)
        self._connect_smtp(context)

    def get_chall_pref(self, domain):
        # pylint: disable=unused-argument,missing-function-docstring
        return [challenge.EmailReply00]

    def perform(self, achalls):  # pylint: disable=missing-function-docstring
        # Start each challenge batch with fresh connections to avoid stale sessions
        # across consecutive renewals in a single run.
        try:
            self.__idle(False)
        except Exception:
            pass
        try:
            self.imap.logout()
        except Exception:
            pass
        try:
            self.smtp.quit()
        except Exception:
            pass
        self.__in_idle = False
        self._connect_imap(self._imap_ssl_context)
        self._connect_smtp(self._imap_ssl_context)
        return [self._perform_emailreply00(achall) for achall in achalls]

    def _perform_emailreply00(self, achall):
        response, _ = achall.challb.response_and_validation(achall.account_key)

        text = 'A challenge request for S/MIME certificate has been sent. In few minutes, ACME server will send a challenge e-mail to requested recipient {}. You do not need to take ANY action, as it will be replied automatically.'.format(achall.domain)
        display_util.notification(text,pause=False)
        sent = False
        for i in range(60):
            try:
                idle_resp = self.imap.idle_check(timeout=1)
            except (imaplib.IMAP4.abort, OSError):
                logger.warning("IMAP IDLE connection dropped. Reconnecting...")
                self.__in_idle = False
                self._connect_imap(self._imap_ssl_context)
                continue
            for msg in idle_resp:
                uid, state = msg
                if state == b'EXISTS':
                    self.__idle(False)
                    respo = self.imap.fetch(uid, ['RFC822'])
                    for message_id, data in respo.items():
                        if (b'RFC822' in data):
                            msg = email.message_from_bytes(data[b'RFC822'],_class=EmailMessage,policy=policy.default)
                            try:
                                response,body = castle.utils.ProcessEmailChallenge(msg, achall)
                                if ('Reply-To' in msg):
                                    to = msg['Reply-To']
                                else:
                                    to = msg['From']
                                me = msg['To']
                                message = 'From: {}\n'.format(me)
                                message += 'To: {}\n'.format(to)
                                message += 'In-Reply-To: {}\n'.format(msg['Message-ID'])
                                message += 'Subject: Re: {}\n\n'.format(msg['Subject'])
                                message += body
                                try:
                                    self.smtp.sendmail(me,to,message)
                                except (SMTPServerDisconnected, OSError):
                                    logger.warning("SMTP connection dropped. Reconnecting...")
                                    self._connect_smtp(self._imap_ssl_context)
                                    self.smtp.sendmail(me,to,message)

                                self.imap.add_flags(message_id,imapclient.SEEN)
                                self.imap.add_flags(message_id,imapclient.DELETED)
                                display_util.notification('The ACME response has been sent successfully!',pause=False)
                                sent = True
                            except (castle.utils.FromAddressMismatch, castle.utils.ReceiptAddressMismatch): #email not from challenge, continue
                                continue
                            except castle.exception.Error as e:
                                raise errors.AuthorizationError(e.message)
            if (sent):
                break
            else:
                self.__idle(True) #no luck, we put the server in IDLE again
        return response

    def cleanup(self, achalls):  # pylint: disable=missing-function-docstring
        try:
            self.__idle(False)
            self.imap.logout()
            self.smtp.quit()
        except (imaplib.IMAP4.abort, OSError):
            pass

    def __idle(self,on):
        if (on == True):
            if (not self.__in_idle):
                self.imap.idle()
            self.__in_idle = True
        else:
            if (self.__in_idle):
                self.imap.idle_done()
            self.__in_idle = False
