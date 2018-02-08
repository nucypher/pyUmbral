from cryptography.hazmat.primitives.asymmetric import ec


class _CONFIG:
    __curve = None
    __params = None

    class UmbralConfigurationError(RuntimeError):
        """Raised when somebody does something dumb re: configuration."""

    @classmethod
    def params(cls):
        if not cls.__params:
            raise cls.UmbralConfigurationError("No default curve has been set; you need one for default params.")
        else:
            return cls.__params

    @classmethod
    def curve(cls):
        if not cls.__curve:
            raise cls.UmbralConfigurationError("No default curve has been set.")
        else:
            return cls.__curve

    @classmethod
    def set_curve(cls, curve: ec.EllipticCurve=None):
        if cls.__curve:
            raise cls.UmbralConfigurationError("You can only set the default curve once.  Do it once and then leave it alone.")
        else:
            from umbral.params import UmbralParameters
            cls.__curve = curve
            cls.__params = UmbralParameters(curve)


def set_default_curve(curve: ec.EllipticCurve=None):
    _CONFIG.set_curve(curve)


def default_curve():
    return _CONFIG.curve()


def default_params():
    return _CONFIG.params()