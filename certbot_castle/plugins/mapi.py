# -*- coding: utf-8 -*-
"""
Created on Thu Nov 11 12:41:59 2021

@author: Pol
"""

import win32com.client as client
import logging
import abc
import time
import email
import os
import pywintypes

from certbot_castle.plugins import castle

logging.basicConfig(
    format='%(asctime)s - %(levelname)s: %(message)s',
    level=logging.DEBUG
)

from certbot import interfaces
from certbot import errors
from certbot.plugins import common
from certbot.display import util as display_util

from certbot_castle import challenge

from email.message import EmailMessage
from email import policy

logger = logging.getLogger(__name__)

class Authenticator(common.Plugin, interfaces.Authenticator, metaclass=abc.ABCMeta):

    description = "Automatic S/MIME challenge by using IMAP integration"

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)

    @classmethod
    def add_parser_arguments(cls, add):
        add('account',help='MAPI account name')

    def more_info(self):  # pylint: disable=missing-function-docstring
        return("This authenticator performs an interactive email-reply-00 challenge. "
               "It uses the a MAPI client already configured (e.g., Outlook)")

    def prepare(self):  # pylint: disable=missing-function-docstring
        try:
            self.outlook = client.GetActiveObject('Outlook.Application')
        except pywintypes.com_error:
            os.startfile('outlook')
            time.sleep(10)
            self.outlook = client.GetActiveObject('Outlook.Application')
        self.mapi = self.outlook.GetNamespace("MAPI")
        self.account = None
        for account in self.mapi.Folders:
            if (account.Name == self.conf('account')):
                self.account = account
                break
        if (not self.account):
            raise errors.AuthorizationError('Account {} does not exist'.format(self.conf('account')))
        
    def get_chall_pref(self, domain):
        # pylint: disable=unused-argument,missing-function-docstring
        return [challenge.EmailReply00]

    def perform(self, achalls):  # pylint: disable=missing-function-docstring
        return [self._perform_emailreply00(achall) for achall in achalls]

    def _perform_emailreply00(self, achall):
        response, _ = achall.challb.response_and_validation(achall.account_key)
        
        text = 'A challenge request for S/MIME certificate has been sent. In few minutes, ACME server will send a challenge e-mail to requested recipient {}. You do not need to take ANY action, as it will be replied automatically.'.format(achall.domain)
        display_util.notification(text,pause=False)
        inbox = self.account.Folders[self.mapi.GetDefaultFolder(6).Name]
        sent = False
        for i in range(60):
            for message in inbox.Items.Restrict("@SQL=""http://schemas.microsoft.com/mapi/proptag/0x0C1F001F"" = '"+achall.challb.chall.from_addr+"' "):
                msg = email.message_from_string(message.PropertyAccessor.GetProperty("http://schemas.microsoft.com/mapi/proptag/0x007D001F")+message.Body,_class=EmailMessage,policy=policy.default)
                try:
                    response,body = castle.utils.ProcessEmailChallenge(msg, achall)
                    reply = message.Reply()
                    reply.Body = body
                    reply.Send()
                    sent = True
                    #message.Unread = False
                    message.Delete()
                except castle.exception.Error as e:
                    raise errors.AuthorizationError(e.message)

            if (sent):
                break
            time.sleep(1)
        return response

    def cleanup(self, achalls):  # pylint: disable=missing-function-docstring
        #self.imap.idle_done()
        #self.outlook.Quit()
        pass
