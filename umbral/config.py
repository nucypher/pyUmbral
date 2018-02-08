from cryptography.hazmat.primitives.asymmetric import ec


class _DEFAULT_CURVE:
    __curve = None

    @classmethod
    def curve(cls):
        if not cls.__curve:
            raise RuntimeError("No default curve has been set.")
        else:
            return cls.__curve

    @classmethod
    def set_curve(cls, curve: ec.EllipticCurve=None):
        if cls.__curve:
            raise RuntimeError("You can only set the default curve once.  Do it once and then leave it alone.")
        else:
            cls.__curve = curve


def set_default_curve(curve: ec.EllipticCurve=None):
    _DEFAULT_CURVE.set_curve(curve)

def default_curve():
    return _DEFAULT_CURVE.curve()