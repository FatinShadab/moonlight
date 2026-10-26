"""Bootstrap check for the installable package."""

import moonlight


def test_package_imports() -> None:
    assert moonlight.__doc__ is not None
