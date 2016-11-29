#!/usr/bin/env python
import sys

from setuptools import setup, find_packages



requires = ['botocore>=0.38.0,<0.39.0',
            'bcdoc>=0.12.0,<0.13.0',
            'boto3>=1.2.1,<2.0.0',]

if sys.version_info[:2] == (2, 6):
    # For python2.6 we have to require argparse since it
    # was not in stdlib until 2.7.
    requires.append('argparse>=1.1')


setup_options = dict(
    name='smartiamcreator',
    #version=smartiamcreator.__version__,
    description='Command Line for creating IAM accounts in AWS.',
    #long_description=open('README.rst').read(),
    author='Facundo',
    author_email='fnishiwaki@smarttech.com',
    url='https://github.com/smartcundo/smartiamcreator',
    scripts=['create_iam_accounts.py'],
    entry_points={
        'console_scripts': [
            'smart-iam = create_iam_accounts:main',
        ]
    },
    packages=find_packages('.', exclude=['tests*']),
    package_dir={'smartiamcreator': '.'},
    package_data={'smartiamcreator': []},
    install_requires=requires,
    license="Apache License 2.0",
    classifiers=(
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
    ),
)

if 'py2exe' in sys.argv:
    # This will actually give us a py2exe command.
    import py2exe
    # And we have some py2exe specific options.
    setup_options['options'] = {
        'py2exe': {
            'optimize': 0,
            'skip_archive': True,
            'packages': ['docutils', 'urllib', 'httplib', 'HTMLParser',
                         'create_iam_accounts', 'ConfigParser', 'xml.etree'],
        }
    }
    setup_options['console'] = ['.']


setup(**setup_options)

