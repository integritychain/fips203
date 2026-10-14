#!/usr/bin/python3
"""NIST encapDecap vectors for the fips203 python module

From the ffi/python/ directory, do:

FIPS203_PYTHON_TESTING_LIBRARY=../../target/debug/libfips203.so PYTHONPATH=. python3 test/nist/encapdecap.py

Decapsulation and the two key checks run through the C API. The C API has no deterministic
encapsulation, so the encapsulation cases are skipped; the Rust harness applies them. A
decapsulation key given as the seed (d, z) must expand to the case's dk.
"""

from __future__ import annotations

import fips203
import gzip
import json
from binascii import a2b_hex

from typing import Any, Callable, Dict

STRENGTH = {"ML-KEM-512": 512, "ML-KEM-768": 768, "ML-KEM-1024": 1024}


def load(name: str, revision: str) -> Dict[str, Any]:
    with gzip.open(
        f"../../tests/nist_vectors/{name}/internalProjection.json.gz",
        "rt",
    ) as f:
        t: Dict[str, Any] = json.load(f)
    assert t["vsId"] == 42
    assert t["algorithm"] == "ML-KEM"
    assert t["mode"] == "encapDecap"
    assert t["revision"] == revision
    return t


def rejected(f: Callable[[], object]) -> bool:
    """Whether the C API rejects the key; any other failure is an error."""
    try:
        f()
    except Exception as e:
        if "DESERIALIZATION_ERROR" in str(e):
            return True
        raise
    return False


def decaps_key(
    group: Dict[str, Any], test: Dict[str, Any], strength: int
) -> fips203.DecapsulationKey:
    if group.get("keyFormat") == "seed":
        seed = fips203.Seed(a2b_hex(test["d"]) + a2b_hex(test["z"]))
        _, dk = seed.keygen(strength)
        assert bytes(dk) == a2b_hex(test["dk"]), "the seed does not expand to dk"
        return dk
    return fips203.DecapsulationKey(a2b_hex(test["dk"]))


def run(name: str, revision: str) -> None:
    t = load(name, revision)
    ran = skipped = 0
    for group in t["testGroups"]:
        strength = STRENGTH[group["parameterSet"]]
        function = group["function"]
        for test in group["tests"]:
            loc = f"{name} tgId={group['tgId']} tcId={test['tcId']}"
            if function == "encapsulation":
                skipped += 1
                continue
            if function == "decapsulation":
                ct = fips203.Ciphertext(a2b_hex(test["c"]))
                k = decaps_key(group, test, strength).decaps(ct)
                assert k == a2b_hex(test["k"]), f"{loc}: k ({test['reason']})"
            elif function == "encapsulationKeyCheck":
                ek = fips203.EncapsulationKey(a2b_hex(test["ek"]))
                assert (
                    rejected(ek.encaps) != test["testPassed"]
                ), f"{loc}: {test['reason']}"
            elif function == "decapsulationKeyCheck":
                dk = fips203.DecapsulationKey(a2b_hex(test["dk"]))
                zero = fips203.Ciphertext(strength)
                assert (
                    rejected(lambda: dk.decaps(zero)) != test["testPassed"]
                ), f"{loc}: {test['reason']}"
            else:
                raise Exception(f"{loc}: unknown function {function}")
            ran += 1
    total = sum(len(g["tests"]) for g in t["testGroups"])
    print(f"{ran} {revision} encapDecap tests passed ({skipped} encapsulation skipped)")
    assert (
        ran + skipped == total
    ), f"{revision}: {ran} ran and {skipped} skipped, of {total}"
    assert ran > 0, f"{revision}: no tests ran"


run("ML-KEM-encapDecap-FIPS203", "FIPS203")
run("ML-KEM-encapDecap-FIPS203-tr1", "FIPS203-tr1")
