import logging

import zope.interface

from acme import messages
from certbot import interfaces
from certbot.plugins import common

from certbot_castle import challenge

import josepy as jose

logger = logging.getLogger(__name__)

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(common.Plugin):

    description = "Performs the S/MIME challenge"

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)

    @classmethod
    def add_parser_arguments(cls, add):
        pass  # No additional argument for the standalone plugin parser

    def more_info(self):  # pylint: disable=missing-function-docstring
        return("This authenticator performs an interactive email-reply-00 challenge. "
               "It does not require mail's provider authorizations. "
               "It request the challenge to ACME server and displays the instructions to resolve it.")

    def prepare(self):  # pylint: disable=missing-function-docstring
        pass

    def get_chall_pref(self, domain):
        # pylint: disable=unused-argument,missing-function-docstring
        return [challenge.EmailReply00]

    def perform(self, achalls):  # pylint: disable=missing-function-docstring
        return [self._perform_emailreply00(achall) for achall in achalls]

    def _perform_emailreply00(self, achall):
        response, _ = achall.challb.response_and_validation(achall.account_key)
        
        notify = zope.component.getUtility(interfaces.IDisplay).notification

        text = 'A challenge request for S/MIME certificate has been sent. In few minutes, ACME server will send a challenge e-mail to requested recipient. Please, copy the ENTIRE subject and paste it below. The subject starts with the label ACME: '
        notify(text,pause=False)
        input = zope.component.getUtility(interfaces.IDisplay).input
        
        code,subject = input('Subject: ', force_interactive=True)
        token64 = subject.split(' ')[-1]
        token1 = jose.b64.b64decode(token64)
        
        full_token = bytearray(achall.chall.token)
        full_token[:len(achall.chall.token)//2] = token1
    
        # We reconstruct the ChallengeBody
        challt = messages.ChallengeBody.from_json({ 'type': 'email-reply-00', 'token': jose.b64.b64encode(bytes(full_token)).decode('ascii'), 'url': achall.challb.uri, 'status': achall.challb.status.to_json() })
        response, validation = challt.response_and_validation(achall.account_key)
        notify('A challenge response has been generated. Please, copy the following text, reply the e-mail you have received from ACME server and paste this text in the TOP of the message\'s body: ',pause=False)
        print('\n-----BEGIN ACME RESPONSE-----\n'
            '{}\n'
            '-----END ACME RESPONSE-----\n'.format(validation))
        return response

    def cleanup(self, achalls):  # pylint: disable=missing-function-docstring
        pass
