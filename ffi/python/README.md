# `fips203` Python module

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
