import re
from os.path import dirname, join

from setuptools import setup

VERSION_RE = re.compile(r"__version__ = \"([\d\.]+)\"")

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
    except OSError:
        return None


def read_version():
    with open("social_core/__init__.py") as file:
        version_line = [
            line for line in file.readlines() if line.startswith("__version__")
        ][0]
        return VERSION_RE.match(version_line).groups()[0]


def read_requirements(filename):
    with open(filename) as file:
        return [line for line in file.readlines() if not line.startswith("-")]


def read_tests_requirements(filename):
    return read_requirements(f"social_core/tests/{filename}")


requirements = read_requirements("requirements-base.txt")
requirements_openidconnect = read_requirements("requirements-openidconnect.txt")
requirements_saml = read_requirements("requirements-saml.txt")
requirements_azuread = read_requirements("requirements-azuread.txt")

tests_requirements = read_tests_requirements("requirements.txt")

requirements_all = requirements_openidconnect + requirements_saml + requirements_azuread

tests_requirements = tests_requirements + requirements_all

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
    python_requires=">=3.6",
    extras_require={
        "openidconnect": [requirements_openidconnect],
        "saml": [requirements_saml],
        "azuread": [requirements_azuread],
        "all": [requirements_all],
        # Kept for compatibility
        "allpy3": [requirements_all],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Topic :: Internet",
        "License :: OSI Approved :: BSD License",
        "Intended Audience :: Developers",
        "Environment :: Web Environment",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
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
