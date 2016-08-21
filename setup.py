# -*- coding: utf-8 -*-
import os
import sys
from os.path import join, dirname, split
from setuptools import setup


version = __import__('social_core').__version__

LONG_DESCRIPTION = """
Python Social Auth is an easy to setup social authentication/registration
mechanism with support for several frameworks and auth providers.

It implements a common interface to define new authentication
providers from third parties. And to bring support for more frameworks
and ORMs.
"""

def long_description():
    try:
        return open(join(dirname(__file__), 'README.md')).read()
    except IOError:
        return None

if os.environ.get('BUILD_VERSION') == '3' or sys.version_info[0] == 3:
    requirements = open('requirements-python3.txt', 'r').readlines()
    tests_requirements = open('social_core/tests/requirements-python3.txt',
                              'r').readlines()
else:
    requirements = open('requirements.txt', 'r').readlines()
    tests_requirements = open('social_core/tests/requirements.txt',
                              'r').readlines()

setup(
    name='social-auth-core',
    version=version,
    author='Matias Aguirre',
    author_email='matiasaguirre@gmail.com',
    description='Python social authentication made simple.',
    license='BSD',
    keywords='openid, oauth, saml, social auth',
    url='https://github.com/python-social-auth/social-core',
    packages=[
        'social_core',
        'social_core.backends',
        'social_core.pipeline',
        'social_core.tests',
        'social_core.tests.actions',
        'social_core.tests.backends',
        'social_core.tests.backends.data'
    ],
    long_description=long_description() or LONG_DESCRIPTION,
    install_requires=requirements,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Topic :: Internet',
        'License :: OSI Approved :: BSD License',
        'Intended Audience :: Developers',
        'Environment :: Web Environment',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3'
    ],
    package_data={
        'social_core/tests': ['social_core/tests/*.txt']
    },
    include_package_data=True,
    tests_require=tests_requirements,
    test_suite='social_core.tests',
    zip_safe=False
)
