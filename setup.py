from setuptools import setup
from setuptools import find_packages

import re, sys
VERSIONFILE = 'certbot_castle/_version.py'
verstrline = open(VERSIONFILE, 'rt').read()
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    version = mo.group(1)
else:
    raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))

INSTALL_REQUIRES = [
    'certbot',
    'josepy',
    'acme>=1.20.0',
    'setuptools',
    'imapclient',
    'dkimpy',
    'cryptography>=3.3',
    'psutil'
]

if sys.platform.startswith('win32'):
    INSTALL_REQUIRES.append("pywin32")

setup(
    name='certbot-castle',
    packages=find_packages(),
    version=version,
    description='ACME E-mail S/MIME client for CASTLE Platform ACME',
    license='GPLv3',
    author="Pol Henarejos",
    author_email='pol.henarejos@cttc.es',
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, !=3.5.*',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Topic :: Communications :: Email',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],
    install_requires=INSTALL_REQUIRES,
    include_package_data=True,
    entry_points={
        'certbot.plugins': [
            'castle-interactive = certbot_castle.plugins.interactive:Authenticator',
            'castle-installer = certbot_castle.plugins.installer:Installer',
            'castle-imap = certbot_castle.plugins.imap:Authenticator',
            'castle-mapi = certbot_castle.plugins.mapi:Authenticator',
            'castle-tb = certbot_castle.plugins.thunderbird:Authenticator',
            'castle-file = certbot_castle.plugins.file:Authenticator'
        ],
    },
)
