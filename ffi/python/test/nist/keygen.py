#!/usr/bin/python3
"""Tests for fips203 python module

From the ffi/python/ directory, do:

PYTHONPATH=. test/nist/keygen.py

"""
from __future__ import annotations

import fips203
import json
import re
from binascii import a2b_hex, b2a_hex

from typing import Dict, Union, List, TypedDict

with open(
    "../../tests/nist_vectors/ML-KEM-keyGen-FIPS203/internalProjection.json"
) as f:
    t = json.load(f)

assert t["vsId"] == 42
assert t["algorithm"] == "ML-KEM"
assert t["mode"] == "keyGen"
assert t["revision"] == "FIPS203"
assert t["isSample"] == False


class KeyGenTestData(TypedDict):
    tcId: int
    deferred: bool
    z: str
    d: str
    ek: str
    dk: str


class KeyGenTest:
    def __init__(self, data: KeyGenTestData):
        self.tcId = data["tcId"]
        self.deferred = data["deferred"]
        self.d = a2b_hex(data["d"])
        self.z = a2b_hex(data["z"])
        self.ek = a2b_hex(data["ek"])
        self.dk = a2b_hex(data["dk"])

    def run(self, group: TestGroup) -> None:
        seed = fips203.Seed(self.d + self.z)
        (ek, dk) = seed.keygen(group.strength)
        if bytes(ek) != self.ek:
            raise Exception(
                f"""test {self.tcId} (group {group.tgId}, str: {group.strength}) ek failed:
                   got: {b2a_hex(bytes(ek))}
                wanted: {b2a_hex(self.ek)}"""
            )
        if bytes(dk) != self.dk:
            raise Exception(
                f"""test {self.tcId} (group {group.tgId}, str: {group.strength}) dk failed:
                   got: {b2a_hex(bytes(dk))}
                wanted: {b2a_hex(self.dk)}"""
            )


class TestGroupData(TypedDict):
    tgId: int
    testType: str
    parameterSet: str
    tests: List[KeyGenTestData]


class TestGroup:
    param_matcher = re.compile("^ML-KEM-(?P<strength>512|768|1024)$")

    def __init__(self, d: TestGroupData) -> None:
        self.tgId: int = d["tgId"]
        self.testType: str = d["testType"]
        assert self.testType == "AFT"  # i don't know what AFT means
        self.parameterSet: str = d["parameterSet"]
        m = self.param_matcher.match(self.parameterSet)
        assert m
        self.strength: int = int(m["strength"])
        self.tests: List[KeyGenTest] = []
        for t in d["tests"]:
            self.tests.append(KeyGenTest(t))

    def run(self) -> None:
        for t in self.tests:
            t.run(self)


groups: List[TestGroup] = []
for g in t["testGroups"]:
    groups.append(TestGroup(g))

for g in groups:
    g.run()
