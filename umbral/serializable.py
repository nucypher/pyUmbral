from abc import abstractmethod, ABC
from typing import Tuple, Type, List, Any, TypeVar


class Serializable(ABC):
    """
    A mixin for composable serialization.
    """

    _T = TypeVar('_T', bound='Serializable')

    @classmethod
    def from_bytes(cls: Type[_T], data: bytes) -> _T:
        """
        Restores the object from serialized bytes.
        """
        obj, remainder = cls.__take__(data)
        if len(remainder) != 0:
            raise ValueError(f"{len(remainder)} bytes remaining after deserializing {cls}")
        return obj

    @classmethod
    def __take_bytes__(cls, data: bytes, size: int) -> Tuple[bytes, bytes]:
        """
        Takes ``size`` bytes from the bytestring and returns them along with the remainder.
        """
        if len(data) < size:
            raise ValueError(f"{cls} cannot take {size} bytes "
                             f"from a bytestring of size {len(data)}")
        return data[:size], data[size:]

    @classmethod
    def __take_types__(cls, data: bytes, *types: Type) -> Tuple[List[Any], bytes]:
        """
        Given a list of ``Serializable`` types, attempts to deserialize them from the bytestring
        one by one and returns the list of the resulting objects and the remaining bytestring.
        """
        objs = []
        for tp in types:
            obj, data = tp.__take__(data)
            objs.append(obj)
        return objs, data

    @classmethod
    @abstractmethod
    def __take__(cls: Type[_T], data: bytes) -> Tuple[_T, bytes]:
        """
        Take however much is necessary from ``data`` and instantiate the object,
        returning it and the remaining bytestring.

        Must be implemented by the derived class.
        """
        raise NotImplementedError

    @abstractmethod
    def __bytes__(self):
        """
        Serializes the object into bytes.
        """
        raise NotImplementedError


def serialize_bool(b: bool) -> bytes:
    return b'\x01' if b else b'\x00'


def take_bool(data: bytes) -> Tuple[bool, bytes]:
    bool_bytes, data = Serializable.__take_bytes__(data, 1)
    if bool_bytes == b'\x01':
        b = True
    elif bool_bytes == b'\x00':
        b = False
    else:
        raise ValueError("Incorrectly serialized boolean; "
                         f"expected b'\\x00' or b'\\x01', got {repr(bool_bytes)}")
    return b, data
