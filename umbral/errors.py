class GenericError(Exception):
    """
    An interal Umbral error, see the message for details.
    """
    pass


class VerificationError(GenericError):
    """
    Integrity of the data cannot be verified, see the message for details.
    """
