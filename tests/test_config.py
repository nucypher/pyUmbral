from umbral.config import _CONFIG
import pytest
import importlib
from cryptography.hazmat.primitives.asymmetric import ec
from umbral.point import Point


def copy_config_for_testing():
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


def test_set_default_curve_exactly_once():
    config = copy_config_for_testing()

    # Can't get the default curve if we haven't set one yet.
    with pytest.raises(config._CONFIG.UmbralConfigurationError):
        config.default_curve()

    # Also, we don't have default params if we haven't passed a curve.
    with pytest.raises(config._CONFIG.UmbralConfigurationError):
        config.default_params()

    # pyumbral even supports untrustworthy curves!
    config.set_default_curve(ec.SECP256R1)

    # Our default curve has been set...
    assert config.default_curve() == ec.SECP256R1
    # ...and used to set the order of our default parameters.
    assert config.default_params().order == Point.get_order_from_curve(ec.SECP256R1)

    # ...but once set, you can't set the default curve again, even if you've found a better one.
    with pytest.raises(config._CONFIG.UmbralConfigurationError):
        config.set_default_curve(ec.SECP256K1)
