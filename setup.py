# -*- coding: utf-8 -*-
import os
import sys
import re
from os.path import join, dirname, split
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

requirements_base = read_requirements('requirements-base.txt')
requirements_python2 = read_requirements('requirements-python2.txt')
requirements_python3 = read_requirements('requirements-python3.txt')
requirements_openidconnect = read_requirements('requirements-openidconnect.txt')

tests_requirements_base = read_tests_requirements('requirements-base.txt')
tests_requirements_python2 = read_tests_requirements('requirements-python2.txt')
tests_requirements_python3 = read_tests_requirements('requirements-python3.txt')
tests_requirements_pypy = read_tests_requirements('requirements-pypy.txt')

requirements = []
requirements.extend(requirements_base)

tests_requirements = []
tests_requirements.extend(tests_requirements_base)

if os.environ.get('BUILD_VERSION') == '3' or sys.version_info[0] == 3:
    requirements.extend(requirements_python3)
    tests_requirements.extend(tests_requirements_python3)
elif '__pypy__' in sys.builtin_module_names:
    tests_requirements.extend(tests_requirements_pypy)
else:
    requirements.extend(requirements_python2)
    tests_requirements.extend(tests_requirements_python2)

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
        'openidconnect': [requirements_openidconnect]
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
        'social_core/tests': ['social_core/tests/*.txt']
    },
    include_package_data=True,
    tests_require=tests_requirements,
    test_suite='social_core.tests',
    zip_safe=False
)
