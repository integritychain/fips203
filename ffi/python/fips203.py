'''FIPS 203 (ML-KEM) Asymmetric Post-Quantum Cryptography

This Python module provides an implementation of FIPS 203, the
Module-Lattice-based Key Encapsulation Mechanism Standard.

The underlying mechanism is intended to offer "post-quantum"
asymmetric encryption and decryption.

## Example

The following example shows using the standard ML-KEM algorithm to
produce identical 32-byte shared secrets:

```
from fips203 import ML_KEM_512

(encapsulation_key, decapsulation_key) = ML_KEM_512.keygen()
(ciphertext, shared_secret_1) = encapsulation_key.encaps()
shared_secret_2 = decapsulation_key.decaps(ciphertext)
assert(shared_secret_1 == shared_secret_2)
```

Encapsulation keys, decapsulation keys, and ciphertexts can all be
serialized by accessing them as `bytes`, and deserialized by
initializing them with the appropriate size bytes object.

A serialization example:

```
from fips203 import ML_KEM_768

(ek,dk) = ML_KEM_768.keygen()
with open('encapskey.bin', 'wb') as f:
    f.write(bytes(ek))
with open('decapskey.bin', 'wb') as f:
    f.write(bytes(dk))
```

A deserialization example, followed by use:

```
import fips203

with open('encapskey.bin', 'b') as f:
    ekdata = f.read()

ek = fips203.EncapsulationKey(ekdata)
(ct, ss) = ek.Encaps()
```

The expected sizes (in bytes) of the different objects in each
parameter set can be accessed with `EK_SIZE`, `DK_SIZE`, `CT_SIZE`,
and `SS_SIZE`:

```
from fips203 import ML_KEM_768

print(f"ML-KEM-768 Ciphertext size (in bytes) is {ML_KEM_768.CT_SIZE}")
```

## Implementation Notes

This is a wrapper around libfips203, built from the Rust fips203-ffi crate.

If that library is not installed in the expected path for libraries on
your system, any attempt to use this module will fail.

This module should have reasonable type annotations and docstrings for
the public interface.  If you discover a problem with type
annotations, or see a way that this kind of documentation could be
improved, please report it!

## See Also

- https://doi.org/10.6028/NIST.FIPS.203.ipd
- https://github.com/integritychain/fips203

## Bug Reporting

Please report issues at https://github.com/integritychain/fips203/issues
'''

'''__version__ should track package.version from  ../Cargo.toml'''
__version__ = '0.2.1'
__author__ = 'Daniel Kahn Gillmor <dkg@fifthhorseman.net>'
__all__ = [
    'ML_KEM_512',
    'ML_KEM_768',
    'ML_KEM_1024',
    'Ciphertext',
    'EncapsulationKey',
    'DecapsulationKey',
]

import ctypes
import ctypes.util
import enum
from typing import Tuple, Dict, Any, Union
from abc import ABC


class _SharedSecret(ctypes.Structure):
    _fields_ = [('data', ctypes.c_uint8 * 32)]


class Err(enum.IntEnum):
    OK = 0
    NULL_PTR_ERROR = 1
    SERIALIZATION_ERROR = 2
    DESERIALIZATION_ERROR = 3
    KEYGEN_ERROR = 4
    ENCAPSULATION_ERROR = 5
    DECAPSULATION_ERROR = 6


class Ciphertext():
    '''ML-KEM Ciphertext

    Serialize this object by asking for it as `bytes`.

    You can convert it to a 32-byte shared secret by passing it to the
    Decaps() function of the appropriate Decapsulation Key.

    '''
    def __init__(self, data: Union[bytes, int]) -> None:
        '''Create ML-KEM Ciphertext from bytes (or strength level).'''
        if isinstance(data, bytes):
            self._strength = _ML_KEM.strength_from_length('CT_SIZE', len(data))
        elif isinstance(data, int):
            self._strength = data
        else:
            raise Exception("Initialize ML-KEM Ciphertext object with "
                            f"bytes or a strength level, not {type(data)}")
        self._ffi = _ML_KEM.strength(self._strength)
        self._ct = self._ffi['Ciphertext']()

        if isinstance(data, bytes):
            self._set(data)

    def __repr__(self) -> str:
        return f'<ML-KEM-{self._strength} Ciphertext>'

    def __bytes__(self) -> bytes:
        return bytes(self._ct.data)

    def _set(self, data: bytes) -> None:
        if len(data) != len(self._ct.data):
            raise ValueError(f"Expected {len(self._ct.data)} bytes, "
                             f"got {len(data)}")
        for i in range(len(data)):
            self._ct.data[i] = data[i]


class EncapsulationKey():
    '''ML-KEM Encapsulation Key

    Serialize this object by asking for it as `bytes`.

    Produce a Ciphertext and a 32-byte shared secret by invoking
    Encaps() on it.
    '''
    def __init__(self, data: Union[bytes, int]) -> None:
        '''Create ML-KEM Encapsulation Key from bytes (or strength level).'''
        if isinstance(data, bytes):
            self._strength = _ML_KEM.strength_from_length('EK_SIZE', len(data))
        elif isinstance(data, int):
            self._strength = data
        else:
            raise Exception("Initialize ML-KEM Encapsulation Key with "
                            f"bytes or a strength level, not {type(data)}")
        self._ffi = _ML_KEM.strength(self._strength)
        self._ek = self._ffi['EncapsKey']()
        if isinstance(data, bytes):
            self._set(data)

    def __repr__(self) -> str:
        return f'<ML-KEM-{self._strength} Encapsulation Key>'

    def __bytes__(self) -> bytes:
        return bytes(self._ek.data)

    def _set(self, data: bytes) -> None:
        if len(data) != len(self._ek.data):
            raise ValueError(f"Expected {len(self._ek.data)} bytes, "
                             f"got {len(data)}")
        for i in range(len(data)):
            self._ek.data[i] = data[i]

    def encaps(self) -> Tuple[Ciphertext, bytes]:
        '''Produce a new Ciphertext and corresponding 32-byte shared secret.'''
        ct = Ciphertext(self._strength)
        ss = _SharedSecret()
        ret = Err(self._ffi['encaps'](ctypes.byref(self._ek),
                                      ctypes.byref(ct._ct),
                                      ctypes.byref(ss)))
        if ret is not Err.OK:
            raise Exception(f"ml_kem_{self._strength}_encaps() "
                            f"returned {ret} ({ret.name})")
        return (ct, bytes(ss.data))


class DecapsulationKey():
    '''ML-KEM Decapsulation Key

    Serialize this object by asking for it as `bytes`.

    Produce a 32-byte shared secret from a Ciphertext by invoking
    Decaps() on it.
    '''
    def __init__(self, data: Union[bytes, int]) -> None:
        '''Create ML-KEM Decapsulation Key from bytes (or strength level).'''
        if isinstance(data, bytes):
            self._strength = _ML_KEM.strength_from_length('DK_SIZE', len(data))
        elif isinstance(data, int):
            self._strength = data
        else:
            raise Exception("Initialize ML-KEM Encapsulation Key with bytes "
                            f"or a strength level, not {type(data)}")
        self._ffi = _ML_KEM.strength(self._strength)
        self._dk = self._ffi['DecapsKey']()
        if isinstance(data, bytes):
            self._set(data)

    def __repr__(self) -> str:
        return f'<ML-KEM-{self._strength} Decapsulation Key>'

    def __bytes__(self) -> bytes:
        return bytes(self._dk.data)

    def _set(self, data: bytes) -> None:
        if len(data) != len(self._dk.data):
            raise ValueError(f"Expected {len(self._dk.data)} bytes, "
                             f"got {len(data)}")
        for i in range(len(data)):
            self._dk.data[i] = data[i]

    def decaps(self, ct: Ciphertext) -> bytes:
        '''Get 32-byte shared secret corresponding to the given Ciphertext.'''
        if self._strength != ct._strength:
            raise Exception(f"Cannot decapsulate {ct} with {self}")
        ss = _SharedSecret()
        ret = Err(self._ffi['decaps'](ctypes.byref(self._dk),
                                      ctypes.byref(ct._ct),
                                      ctypes.byref(ss)))
        if ret is not Err.OK:
            raise Exception(f"ml_kem_{self._strength}_decaps() "
                            f"returned {ret} ({ret.name})")
        return bytes(ss.data)


class _ML_KEM():
    params: Dict[int, Dict[str, int]] = {
        512: {
            'EK_SIZE': 800,
            'DK_SIZE': 1632,
            'CT_SIZE': 768,
            },
        768: {
            'EK_SIZE': 1184,
            'DK_SIZE': 2400,
            'CT_SIZE': 1088,
            },
        1024: {
            'EK_SIZE': 1568,
            'DK_SIZE': 3168,
            'CT_SIZE': 1568,
            },
        }
    lib = ctypes.CDLL(ctypes.util.find_library('fips203'))
    if not hasattr(lib, 'ml_kem_512_keygen'): lib = ctypes.CDLL("../../target/debug/libfips203.so")

    # use Any below because i don't know how to specify the type of the FuncPtr
    ffi: Dict[int, Dict[str, Any]] = {}

    @classmethod
    def strength(cls, level: int) -> Dict[str, Any]:
        if level not in cls.ffi:
            class _EncapsKey(ctypes.Structure):
                _fields_ = [('data', ctypes.c_uint8 *
                             cls.params[level]['EK_SIZE'])]

            class _DecapsKey(ctypes.Structure):
                _fields_ = [('data', ctypes.c_uint8 *
                             cls.params[level]['DK_SIZE'])]

            class _Ciphertext(ctypes.Structure):
                _fields_ = [('data', ctypes.c_uint8 *
                             cls.params[level]['CT_SIZE'])]
            ffi: Dict[str, Any] = {}

            ffi['keygen'] = cls.lib[f'ml_kem_{level}_keygen']
            ffi['keygen'].argtypes = [ctypes.POINTER(_EncapsKey),
                                      ctypes.POINTER(_DecapsKey)]
            ffi['keygen'].restype = ctypes.c_uint8

            ffi['encaps'] = cls.lib[f'ml_kem_{level}_encaps']
            ffi['encaps'].argtypes = [ctypes.POINTER(_EncapsKey),
                                      ctypes.POINTER(_Ciphertext),
                                      ctypes.POINTER(_SharedSecret)]
            ffi['encaps'].restype = ctypes.c_uint8

            ffi['decaps'] = cls.lib[f'ml_kem_{level}_decaps']
            ffi['decaps'].argtypes = [ctypes.POINTER(_DecapsKey),
                                      ctypes.POINTER(_Ciphertext),
                                      ctypes.POINTER(_SharedSecret)]
            ffi['decaps'].restype = ctypes.c_uint8

            ffi['EncapsKey'] = _EncapsKey
            ffi['DecapsKey'] = _DecapsKey
            ffi['Ciphertext'] = _Ciphertext

            cls.ffi[level] = ffi

        return cls.ffi[level]

    @classmethod
    def strength_from_length(cls, object_type: str, object_len: int) -> int:
        for strength in cls.params:
            if cls.params[strength][object_type] == object_len:
                return strength
        raise Exception(f"No ML-KEM parameter set has {object_type} "
                        f"of {object_len} bytes")

    @classmethod
    def _keygen(cls, strength: int) -> Tuple[EncapsulationKey,
                                             DecapsulationKey]:
        ek = EncapsulationKey(strength)
        dk = DecapsulationKey(strength)

        ret = Err(cls.strength(strength)['keygen'](ctypes.byref(ek._ek),
                                                   ctypes.byref(dk._dk)))
        if ret is not Err.OK:
            raise Exception(f"ml_kem_{strength}_keygen() returned "
                            f"{ret} ({ret.name})")
        return (ek, dk)


class ML_KEM(ABC):
    '''Abstract base class for all ML-KEM (FIPS 203) parameter sets.'''

    _strength: int
    EK_SIZE: int
    DK_SIZE: int
    CT_SIZE: int
    SS_SIZE: int = 32

    @classmethod
    def keygen(cls) -> Tuple[EncapsulationKey, DecapsulationKey]:
        '''Generate a pair of Encapsulation and Decapsulation Keys.'''
        return _ML_KEM._keygen(cls._strength)


class ML_KEM_512(ML_KEM):
    '''ML-KEM-512 (FIPS 203) Implementation.'''
    _strength: int = 512
    EK_SIZE: int = 800
    DK_SIZE: int = 1632
    CT_SIZE: int = 768


class ML_KEM_768(ML_KEM):
    '''ML-KEM-768 (FIPS 203) Implementation.'''
    _strength: int = 768
    EK_SIZE: int = 1184
    DK_SIZE: int = 2400
    CT_SIZE: int = 1088


class ML_KEM_1024(ML_KEM):
    '''ML-KEM-1024 (FIPS 203) Implementation.'''
    _strength: int = 1024
    EK_SIZE: int = 1568
    DK_SIZE: int = 3168
    CT_SIZE: int = 1568
