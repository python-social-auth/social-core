from __future__ import annotations

import ast
from importlib.resources import files
from pathlib import Path
from xml.etree import ElementTree as ET  # ruff: ignore[suspicious-xml-etree-import]

from social_core.backends.base import BaseAuth
from social_core.backends.email import EmailAuth
from social_core.backends.github_enterprise import GithubEnterpriseOrganizationOAuth2
from social_core.backends.salesforce import SalesforceOAuth2Sandbox
from social_core.backends.username import UsernameAuth


def test_custom_backend_metadata_is_optional() -> None:
    class CustomAuth(BaseAuth):
        name = "custom"

    assert CustomAuth.title is None
    assert CustomAuth.icon is None


def test_enterprise_backend_reuses_provider_icon() -> None:
    assert GithubEnterpriseOrganizationOAuth2.title == "GitHub Enterprise Organization"
    assert GithubEnterpriseOrganizationOAuth2.icon == "github.svg"
    assert GithubEnterpriseOrganizationOAuth2.name == "github-enterprise-org"


def test_shipped_backend_metadata_and_assets() -> None:
    # Inspect declarations without importing optional SDKs or initializing strategies.
    backends = Path(str(files("social_core").joinpath("backends")))
    icons = (
        files("social_core")
        .joinpath("static")
        .joinpath("social_auth")
        .joinpath("icons")
    )
    for module in backends.glob("*.py"):
        for definition in ast.parse(module.read_text()).body:
            if not isinstance(definition, ast.ClassDef):
                continue
            attributes = {
                target.id: statement.value
                for statement in definition.body
                if isinstance(statement, ast.Assign)
                for target in statement.targets
                if isinstance(target, ast.Name)
            }
            if "name" not in attributes or not ast.literal_eval(attributes["name"]):
                continue
            assert "title" in attributes, (module.name, definition.name)
            assert ast.literal_eval(attributes["title"]).strip(), definition.name
            if "icon" in attributes:
                filename = ast.literal_eval(attributes["icon"])
                assert Path(filename).name == filename
                asset = icons.joinpath(filename)
                assert asset.is_file(), filename
                svg = ET.fromstring(asset.read_text())  # ruff: ignore[suspicious-xml-element-tree-usage]
                assert svg.tag == "{http://www.w3.org/2000/svg}svg"


def test_generic_icons_are_application_owned() -> None:
    assert EmailAuth.icon is None
    assert UsernameAuth.icon is None
    icons = (
        files("social_core")
        .joinpath("static")
        .joinpath("social_auth")
        .joinpath("icons")
    )
    assert not icons.joinpath("password.svg").is_file()
    assert not icons.joinpath("email.svg").is_file()


def test_sandbox_inherits_provider_logo() -> None:
    assert SalesforceOAuth2Sandbox.icon == "salesforce.svg"
    assert SalesforceOAuth2Sandbox.title == "Salesforce (Sandbox)"
