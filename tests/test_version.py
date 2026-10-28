"""The version string must have exactly one source of truth.

`qrsig --version` reported 0.1.0 on a 0.1.2 install through two releases,
because `__init__.py` hardcoded a literal that pyproject.toml never
updated. A version number that disagrees with the installed artifact is a
claim about a program that isn't the one running.
"""

import pytest
from importlib.metadata import version as pkg_version

import qrsig
from qrsig import cli


def test_dunder_version_matches_installed_metadata():
    assert qrsig.__version__ == pkg_version("qrsig")


def test_dunder_version_is_not_a_stale_literal():
    # The exact failure that shipped in 0.1.0, 0.1.1 and 0.1.2.
    assert qrsig.__version__ != "0.1.0"


def test_cli_version_flag_reports_the_package_version(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    out = capsys.readouterr().out.strip()
    assert out == "qrsig %s" % pkg_version("qrsig")
