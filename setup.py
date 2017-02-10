# -*- coding: utf-8 -*-
import os
import sys
import re
from os.path import join, dirname
from setuptools import setup


VERSION_RE = re.compile('__version__ = \'([\d\.]+)\'')

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


def read_version():
    with open('social_core/__init__.py') as file:
        version_line = [line for line in file.readlines()
                        if line.startswith('__version__')][0]
        return VERSION_RE.match(version_line).groups()[0]


def read_requirements(filename):
    with open(filename, 'r') as file:
        return [line for line in file.readlines() if not line.startswith('-')]


def read_tests_requirements(filename):
    return read_requirements('social_core/tests/{0}'.format(filename))


PY = os.environ.get("BUILD_VERSION") or sys.version_info[0]
requirements_base = read_requirements('requirements-base.txt')
requirements = read_requirements('requirements-python%s.txt' % PY) + \
               requirements_base
requirements_openidconnect = read_requirements('requirements-openidconnect.txt')
requirements_saml = read_requirements('requirements-saml-python%s.txt' % PY)

tests_requirements_base = read_tests_requirements('requirements-base.txt')
tests_requirements = read_tests_requirements(
    'requirements-python%s.txt' % PY) + tests_requirements_base
requirements_all = requirements_openidconnect + requirements_saml

tests_requirements = tests_requirements + requirements_all

setup(
    name='social-auth-core',
    version=read_version(),
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
    extras_require={
        'openidconnect': [requirements_openidconnect],
        'saml': [requirements_saml],
        'all': [requirements_all]
    },
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
        'social_core/tests': [
            'social_core/tests/*.txt',
            'social_core/tests/testkey.pem'
        ]
    },
    include_package_data=True,
    tests_require=tests_requirements,
    test_suite='social_core.tests',
    zip_safe=False
)
