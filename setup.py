from setuptools import setup

setup(
    name='locsec-aes',
    version='0.1.3.4',
    packages=['locsec_aes.tests', 'locsec_aes'],
    url='',
    license='GPLv3',
    author='locchan',
    author_email='lkkccc@yandex.by',
    install_requires=[
        'pycryptodomex'
    ],
    description='LocSec AES. AES Encryptor for LocSec'
)
