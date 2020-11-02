from setuptools import setup
from setuptools import find_packages


setup(
    name='certbot-castle',
    packages=find_packages(),
    install_requires=[
        'certbot>=0.26.0',
        'zope.interface',
    ],
    entry_points={
        'certbot.plugins': [
            'castle-interactive = certbot_castle.plugins.interactive:Authenticator',
        ],
    },
)
