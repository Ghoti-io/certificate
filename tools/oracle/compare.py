# SPDX-License-Identifier: LGPL-3.0-only
#
# Copyright (C) 2026 Corey Pennycuff
"""Exact comparison of two hex digests.

A prefix is not a match. Empty is not a match. The comparison is the one
place a truncated tag would otherwise be accepted, so the tests of this
function are the tests of that refusal.
"""


def hex_equal(left, right):
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    if len(left) == 0 or len(left) != len(right):
        return False
    return left.lower() == right.lower()


def self_test():
    """Raise AssertionError if the comparator accepts a match it must not."""
    assert hex_equal("aa", "aa")
    assert hex_equal("AA", "aa")
    assert not hex_equal("aa", "ab")
    assert not hex_equal("aa", "aa00")
    assert not hex_equal("aa00", "aa")
    assert not hex_equal("", "")
    assert not hex_equal("aa", "")
    assert not hex_equal("abcd", "ab")
