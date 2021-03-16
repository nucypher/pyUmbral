from .hashing import unsafe_hash_to_point


class Parameters:

    def __init__(self):
        self.u = unsafe_hash_to_point(b'PARAMETERS', b'POINT_U')


PARAMETERS = Parameters()
