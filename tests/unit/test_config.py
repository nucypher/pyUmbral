"""
This file is part of pyUmbral.

pyUmbral is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

pyUmbral is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with pyUmbral. If not, see <https://www.gnu.org/licenses/>.
"""

import importlib
import pytest
import warnings

from umbral.config import _CONFIG
from umbral.curve import SECP256K1, SECP256R1


def _copy_config_for_testing():
    """
    NEVER do this.  This is for testing only.
    This is absolutely not a thing to actually do in production code.  At all.  Ever.
    """
    config_module_spec = importlib.util.find_spec("umbral.config")
    config_copy = importlib.util.module_from_spec(config_module_spec)
    config_module_spec.loader.exec_module(config_copy)
    assert hasattr(config_copy, "default_curve")
    assert config_copy is not _CONFIG
    return config_copy


def test_try_to_use_curve_with_no_default_curve():
    config = _copy_config_for_testing()

    # No curve is set.
    assert config._CONFIG._CONFIG__curve is None

    # Getting the default curve if we haven't set one yet sets one and gives us a warning.
    with warnings.catch_warnings(record=True) as caught_warnings:
        assert len(caught_warnings) == 0
        config.default_curve()
        assert len(caught_warnings) == 1
        assert caught_warnings[0].message.args[0] == config._CONFIG._CONFIG__WARNING_IF_NO_DEFAULT_SET
        assert caught_warnings[0].category == RuntimeWarning

    # Now, a default curve has been set.
    assert config._CONFIG._CONFIG__curve == SECP256K1


def test_try_to_use_default_params_with_no_default_curve():
    config = _copy_config_for_testing()

    # Again, no curve is set.
    assert config._CONFIG._CONFIG__curve is None

    # This time, we'll try to use default_params() and get the same warning as above.
    with warnings.catch_warnings(record=True) as caught_warnings:
        assert len(caught_warnings) == 0
        config.default_params()
        assert len(caught_warnings) == 1
        assert caught_warnings[0].message.args[0] == config._CONFIG._CONFIG__WARNING_IF_NO_DEFAULT_SET
        assert caught_warnings[0].category == RuntimeWarning

    # Now, a default curve has been set.
    assert config._CONFIG._CONFIG__curve == SECP256K1


def test_cannot_set_default_curve_twice():
    config = _copy_config_for_testing()

    # pyumbral even supports NIST curves!
    config.set_default_curve(SECP256R1)

    # Our default curve has been set...
    assert config.default_curve() == SECP256R1

    # ...but once set, you can't set the default curve again, even if you've found a better one.
    with pytest.raises(config._CONFIG.UmbralConfigurationError):
        config.set_default_curve(SECP256K1)
