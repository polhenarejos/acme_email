# -*- coding: utf-8 -*-
"""
Created on Tue Nov 16 15:51:27 2021

@author: Pol
"""

from certbot import errors
import sqlite3
import time
import os
import configparser
import logging
import abc
import email
import sys
import re
from urllib.parse import urlparse, unquote, quote
import mailbox
import subprocess
import shutil

from certbot_castle.plugins import castle

logging.basicConfig(
    format='%(asctime)s - %(levelname)s: %(message)s',
    level=logging.DEBUG
)

from certbot import interfaces
from certbot.plugins import common
from certbot.display import util as display_util

from certbot_castle import challenge

logger = logging.getLogger(__name__)

class Authenticator(common.Plugin, interfaces.Authenticator, metaclass=abc.ABCMeta):

    description = "Automatic S/MIME challenge by using Thunderbird integration"

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        if (sys.platform.startswith('win32')):
            self.tb_path = os.path.join(os.getenv('APPDATA') or os.path.expanduser('~'), 'Thunderbird')
        elif sys.platform == 'darwin':
            self.tb_path = os.path.join(os.path.expanduser('~'), 'Library', 'Thunderbird')
        else:
            self.tb_path = os.path.join(os.path.expanduser('~'), '.thunderbird')
        self.tb_bin = self.__tb_bin()

    @classmethod
    def add_parser_arguments(cls, add):
        add('unsafe',help='Run the authenticator without security checks',action='store_true')
        add('bin',help='Thunderbird binary/executable path')
        add('profile',help='Thunderbird profile path')

    def more_info(self):  # pylint: disable=missing-function-docstring
        return("This authenticator performs an interactive email-reply-00 challenge. "
               "It uses the a Thunderbird client already configured")

    def prepare(self):  # pylint: disable=missing-function-docstring
        profile = self.conf('profile')
        if (not profile):
            config = configparser.ConfigParser()
            config.read(os.path.join(self.tb_path, 'profiles.ini'))
            for sect in config.sections():
                if sect.lower().startswith('install') and config.getboolean(sect, 'locked', fallback=False):
                    profile = config.get(sect, 'default', fallback=None)
                    if profile:
                        break
            if not profile:
                for sect in config.sections():
                    if config.has_option(sect, 'path') and config.getboolean(sect, 'default', fallback=False):
                        profile = config[sect]['path']
                        break
            if not profile:
                for sect in config.sections():
                    if sect.lower().startswith('install'):
                        profile = config.get(sect, 'default', fallback=None)
                        if profile:
                            break
            if (not profile):
                raise errors.AuthorizationError('It is not possible to find current Thunderbird profile. Use --tb-profile instead.')
            if not os.path.isabs(profile):
                profile = os.path.join(self.tb_path, profile)
        self.tb_prefs = None
        try:
            pref_file = profile+'/prefs.js'
            self.tb_prefs = self.__parse_tb_prefs(pref_file)
        except FileNotFoundError:
            if not self.conf('unsafe'):
                raise errors.AuthorizationError('No pref file found. You may use --tb-unsafe but be aware that no security checks will be performed. USE IT AT YOUR OWN RISK.')

        db_path = profile+'/global-messages-db.sqlite'
        try:
            self.con = sqlite3.connect(db_path, timeout=30)
            self.cursor = self.con.cursor()
            self.cursor.execute("SELECT * FROM messagesText_content ORDER BY docid DESC LIMIT 1")
            self.cursor.fetchone()
        except sqlite3.OperationalError as e:
            message = 'It is not possible to connect to Thunderbird database.'
            if 'locked' in str(e).lower():
                message += ' Close stale Thunderbird processes or disable storage.sqlite.exclusiveLock.enabled to allow shared access.'
            raise errors.AuthorizationError(message) from e

    def get_chall_pref(self, domain):
        # pylint: disable=unused-argument,missing-function-docstring
        return [challenge.EmailReply00]

    def perform(self, achalls):  # pylint: disable=missing-function-docstring
        return [self._perform_emailreply00(achall) for achall in achalls]

    def _perform_emailreply00(self, achall):
        response, _ = achall.challb.response_and_validation(achall.account_key)

        text = 'A challenge request for S/MIME certificate has been sent. In few minutes, ACME server will send a challenge e-mail to requested recipient {}. Once ready, a reply will pop-up. Just click on Send.'.format(achall.domain)
        display_util.notification(text,pause=False)
        body = None
        mid = None
        for i in range(60):
            self.cursor.execute(f"SELECT * FROM messagesText_content WHERE c3author LIKE '%<{achall.challb.chall.from_addr}>%' ORDER BY docid DESC LIMIT 1")
            res_content = self.cursor.fetchone()
            if (res_content):
                self.cursor.execute(f"SELECT * FROM messages WHERE id = {res_content[0]}")
                result = self.cursor.fetchone()
                if (result):
                    mid = result[5]
                    fid = result[1]
                    self.cursor.execute(f"SELECT * FROM folderLocations WHERE id = {fid}")
                    result = self.cursor.fetchone()
                    if (result):
                        folderURI = result[1]
                        u = urlparse(folderURI)
                        p = u.netloc.split('@')
                        user = unquote(p[0])
                        hostname = p[1]
                        found = False
                        for item in self.tb_prefs.get('mail',{}).get('server',{}):
                            server = self.tb_prefs.get('mail',{}).get('server',{}).get(item,{})
                            if (server.get('hostname',None) == hostname and server.get('type',None)== u.scheme and server.get('userName',None) == user):
                                folderPath = server.get('directory',None)+'/INBOX'
                                if os.path.isfile(folderPath):
                                    mbox = mailbox.mbox(folderPath)
                                    for mmsg in mbox:
                                        if (mmsg.get('Message-Id', None) == f'<{mid}>'):
                                            msg = email.message_from_string(str(mmsg))
                                            try:
                                                response,body = castle.utils.ProcessEmailChallenge(msg, achall)
                                            except castle.exception.BadSubject: #Not an ACME email
                                                pass
                                            except castle.exception.Error as e:
                                                raise errors.AuthorizationError(e.message)
                                            found = True
                                            break
                                    if (not found):
                                        if not self.conf('unsafe'):
                                            raise errors.AuthorizationError('ACME email was found but it is not possible to recover the whole message. You may use --tb-unsafe but be aware that no security checks will be performed. USE IT AT YOUR OWN RISK.')
                                else:
                                    if not self.conf('unsafe'):
                                        raise errors.AuthorizationError('No INBOX file found. You may use --tb-unsafe but be aware that no security checks will be performed. USE IT AT YOUR OWN RISK.')

                            if (found):
                                break
                        if (not found):
                            if not self.conf('unsafe'):
                                raise errors.AuthorizationError('ACME email was found but it is not possible to recover the whole message. You may use --tb-unsafe but be aware that no security checks will be performed. USE IT AT YOUR OWN RISK.')
                    else:
                        if not self.conf('unsafe'):
                            raise errors.AuthorizationError('It is not possible to recover the folder of your INBOX. You may use --tb-unsafe but be aware that no security checks will be performed. USE IT AT YOUR OWN RISK.')
                else:
                    if not self.conf('unsafe'):
                        raise errors.AuthorizationError('It is not possible to recover the messageID. You may use --tb-unsafe but be aware that no security checks will be performed. USE IT AT YOUR OWN RISK.')
                if (not body): #tb-unsafe to get this point
                    if not self.conf('unsafe'): #rarely will raise
                        raise errors.AuthorizationError('Cannot create reply message. You may use --tb-unsafe but be aware that no security checks will be performed. USE IT AT YOUR OWN RISK.')

                    response,body = castle.utils.ChallengeFromSubject(res_content[2], achall)
                cmd_url = ','.join((
                    f'from={quote(str(achall.domain), safe="")}',
                    f'to={quote(str(achall.challb.chall.from_addr), safe="")}',
                    f'subject={quote(str(res_content[2]), safe="")}',
                    f'body={quote(body, safe="")}',
                    'format=text'
                ))
                if (mid):
                    cmd_url += f',in-reply-to={quote("<{}>".format(mid), safe="")}'
                cmd = [
                    self.tb_bin,
                    '-compose',
                    cmd_url
                    ]
                subprocess.call(cmd)
                time.sleep(5)
                break
            time.sleep(1)
        return response

    def cleanup(self, achalls):  # pylint: disable=missing-function-docstring
        self.con.close()

    def __parse_tb_prefs(self, pref_file):
        r = {}
        with open(pref_file, 'r', encoding='utf-8', errors='replace') as f:
            def set(my_dict, key_string, value):
                keys = key_string.split(".")
                for key in keys[:-1]:
                    my_dict = my_dict.setdefault(key, {})
                my_dict[keys[-1]] = value
            for line in f.readlines():
                m = re.findall(r'user_pref\("(.+)",\s*(.+)\)', line)
                if (len(m) > 0):
                    try:
                        val = m[0][1]
                        if (val[0] == '"'):
                            val = val[1:]
                        if (val[-1] == '"'):
                            val = val[:-1]
                        set(r,m[0][0],val)
                    except TypeError:
                        pass
        return r

    def __tb_bin(self):
        if (self.conf('bin')):
            return self.conf('bin')

        import psutil
        tb_bin = shutil.which('thunderbird')
        if tb_bin:
            return tb_bin
        for p in psutil.process_iter():
            try:
                if ('thunderbird' in p.name().lower()):
                    tb_bin = p.exe()
                    if tb_bin:
                        return tb_bin
            except psutil.Error:
                continue

        if (not tb_bin):
            raise errors.AuthorizationError('Cannot find Thunderbird binary/executable. Use --tb-bin to provide the path.')

        return tb_bin
