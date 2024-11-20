# -*- coding: utf-8 -*-
"""
Created 2024-09-28
@author: T.P. van der Zwaan (tijzwa@vpo.nl)
"""

import logging
import abc
import os
import time

from acme import messages
from certbot import interfaces
from certbot.plugins import common
from certbot.display import util as display_util

from certbot_castle import challenge

import josepy as jose

from cryptography.hazmat.primitives import hashes  # type: ignore

logger = logging.getLogger(__name__)

class Authenticator(common.Plugin, interfaces.Authenticator, metaclass=abc.ABCMeta):

    description = "Performs the S/MIME challenge"

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)

    @classmethod
    def add_parser_arguments(cls, add):
        pass  # No additional argument for the standalone plugin parser

    def more_info(self):  # pylint: disable=missing-function-docstring
        return("This authenticator performs an interactive email-reply-00 challenge. "
               "It does not require mail's provider authorizations. "
               "It request the challenge to ACME server and waits for a file to be filled with the aquired challenge.")

    def prepare(self):  # pylint: disable=missing-function-docstring
        pass

    def get_chall_pref(self, domain):
        # pylint: disable=unused-argument,missing-function-docstring
        return [challenge.EmailReply00]

    def perform(self, achalls):  # pylint: disable=missing-function-docstring
        return [self._perform_emailreply00(achall) for achall in achalls]

    def _perform_emailreply00(self, achall):
        temp_dir = os.path.normpath(f"{self.config.config_dir}/tmp")
        subject_file = os.path.normpath(f"{temp_dir}/resp_{achall.domain}_subject.txt")
        body_file = os.path.normpath(f"{temp_dir}/resp_{achall.domain}_body.txt")

        os.makedirs(temp_dir, exist_ok=True) 

        with open(subject_file, "w"):
            pass  # This will create or truncate the file, making it empty

        with open(body_file, "w"):
            pass  # This will create or truncate the file, making it empty


        response, _ = achall.challb.response_and_validation(achall.account_key)
        
        text = 'A challenge request for S/MIME certificate has been sent. In few minutes, ACME server will send a challenge e-mail to requested recipient {}. Waiting until {} contains the challenge.'.format(achall.domain, subject_file)
        display_util.notification(text,pause=False)

        while True:
            with open(subject_file, "r") as f:
                subject = f.read()
                if len(subject) > 0:
                    break
            time.sleep(10)

        token64 = subject.split(' ')[-1]
        token1 = jose.b64.b64decode(token64)
        full_token = token1+achall.chall.token
    
        # We reconstruct the ChallengeBody
        challt = messages.ChallengeBody.from_json({ 'type': 'email-reply-00', 'token': jose.b64.b64encode(bytes(full_token)).decode('ascii'), 'url': achall.challb.uri, 'status': achall.challb.status.to_json(), 'from': achall.challb.chall.from_addr })
        response, validation = challt.response_and_validation(achall.account_key)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(validation.encode())
        thumbprint = jose.b64encode(digest.finalize()).decode()
        display_util.notification(f"A challenge response has been generated. Please, copy the text from {body_file} and reply the e-mail you have received from ACME server.",pause=False)
        with open(body_file, "w") as file:
            file.write('\n-----BEGIN ACME RESPONSE-----\n'
            '{}\n'
            '-----END ACME RESPONSE-----\n'.format(thumbprint))
        
        return response

    def cleanup(self, achalls):  # pylint: disable=missing-function-docstring
        pass
