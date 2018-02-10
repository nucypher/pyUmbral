from warnings import warn

from cryptography.hazmat.primitives.asymmetric import ec


class _CONFIG:
    __curve = None
    __params = None
    __CURVE_TO_USE_IF_NO_DEFAULT_IS_SET_BY_USER = ec.SECP256K1
    __WARNING_IF_NO_DEFAULT_SET = "No default curve has been set.  Using SECP256K1.  A slight performance penalty has been incurred for only this call.  Set a default curve with umbral.config.set_default_curve()."

    class UmbralConfigurationError(RuntimeError):
        """Raised when somebody does something dumb re: configuration."""

    @classmethod
    def __set_curve_by_default(cls):
        warn(cls.__WARNING_IF_NO_DEFAULT_SET, RuntimeWarning)
        cls.set_curve(cls.__CURVE_TO_USE_IF_NO_DEFAULT_IS_SET_BY_USER)

    @classmethod
    def params(cls):
        if not cls.__params:
            cls.__set_curve_by_default()
        return cls.__params

    @classmethod
    def curve(cls):
        if not cls.__curve:
            cls.__set_curve_by_default()
        return cls.__curve

    @classmethod
    def set_curve(cls, curve: ec.EllipticCurve = None):
        if cls.__curve:
            raise cls.UmbralConfigurationError(
                "You can only set the default curve once.  Do it once and then leave it alone.")
        else:
            from umbral.params import UmbralParameters
            cls.__curve = curve
            cls.__params = UmbralParameters(curve)


def set_default_curve(curve: ec.EllipticCurve = None):
    _CONFIG.set_curve(curve)


def default_curve():
    return _CONFIG.curve()


def default_params():
    return _CONFIG.params()
