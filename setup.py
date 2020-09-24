# -*- coding: utf-8 -*-
import re

from os.path import join, dirname

from setuptools import setup


VERSION_RE = re.compile(r"__version__ = \'([\d\.]+)\'")

LONG_DESCRIPTION = """
Python Social Auth is an easy to setup social authentication/registration
mechanism with support for several frameworks and auth providers.

It implements a common interface to define new authentication
providers from third parties. And to bring support for more frameworks
and ORMs.
"""


def long_description():
    try:
        return open(join(dirname(__file__), "README.md")).read()
    except IOError:
        return None


def read_version():
    with open("social_core/__init__.py") as file:
        version_line = [
            line for line in file.readlines() if line.startswith("__version__")
        ][0]
        return VERSION_RE.match(version_line).groups()[0]


requirements = [
    "requests>=2.9.1",
    "oauthlib>=1.0.3",
    "requests-oauthlib>=0.6.1",
    "six>=1.10.0",
    "PyJWT>=1.4.0",
    "cryptography>=1.4",
    "python-openid>=2.2.5;python_version<='2.7'",
    "defusedxml>=0.5.0rc1;python_version>'2.7'",
    "python3-openid>=3.0.10;python_version>'2.7'",
]
# May be able to just use environment markers in requirements-base.txt
# at least on  setuptools 36.2.0 and up.
requirements_openidconnect = [
    "python-jose>=3.0.0",
    "pyjwt>=1.7.1",
]
requirements_saml = [
    "python-saml>=2.2.0;python_version<='2.7'",
    "defusedxml>=0.6.0;python_version<='2.7'",
    "python3-saml>=1.2.1;python_version>'2.7'",
]
requirements_azuread = ["cryptography>=2.1.1"]
requirements_all = requirements_openidconnect + requirements_saml + requirements_azuread

tests_requirements = [
    "coverage>=3.6",
    "httpretty>=0.9.6",
    "mock;python_version<='2.7'",
    "pytest-cov>=2.7.1",
    "pytest>=4.5;python_version>'2.7'",
    "pytest<5.0;python_version<='2.7'",
    "unittest2",
]

setup(
    name="social-auth-core",
    version=read_version(),
    author="Matias Aguirre",
    author_email="matiasaguirre@gmail.com",
    description="Python social authentication made simple.",
    license="BSD",
    keywords="openid, oauth, saml, social auth",
    url="https://github.com/python-social-auth/social-core",
    packages=[
        "social_core",
        "social_core.backends",
        "social_core.pipeline",
        "social_core.tests",
        "social_core.tests.actions",
        "social_core.tests.backends",
        "social_core.tests.backends.data",
    ],
    long_description=long_description() or LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    install_requires=requirements,
    extras_require={
        "openidconnect": requirements_openidconnect,
        "saml": requirements_saml,
        "azuread": requirements_azuread,
        "all": requirements_all,
        "test": requirements_all + tests_requirements,
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Topic :: Internet",
        "License :: OSI Approved :: BSD License",
        "Intended Audience :: Developers",
        "Environment :: Web Environment",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],
    package_data={
        "social_core/tests": [
            "social_core/tests/*.txt",
            "social_core/tests/testkey.pem",
        ]
    },
    include_package_data=True,
    tests_require=tests_requirements,
    test_suite="social_core.tests",
    zip_safe=False,
)
