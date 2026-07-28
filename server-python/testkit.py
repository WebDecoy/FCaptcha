"""Shared plumbing for the Python test files.

These tests are plain functions collected by a decorator rather than
``unittest.TestCase`` methods, which keeps them readable and dependency-free.
The cost was that ``python -m unittest discover`` could not see them: two files
guarded their runner under ``__main__`` and reported *Ran 0 tests* without
complaint, and two ran at import time and called ``sys.exit`` mid-discovery,
which surfaced as an error against a suite that actually passed. Either way the
count was wrong and nothing in CI ran them at all.

So a registry does both jobs. ``main`` keeps the readable output for a human
running one file; ``testcase`` exposes the same functions to ``unittest`` so
discovery counts them instead of skipping them silently.
"""

import sys
import unittest


class TestRegistry:
    """Collects test functions and makes them runnable two ways.

    Used as a decorator::

        test = TestRegistry()

        @test
        def a_thing_holds():
            assert ...

        ThingTests = test.testcase("ThingTests")   # for unittest discovery

        if __name__ == "__main__":
            test.main()
    """

    def __init__(self):
        self._tests = []

    def __call__(self, fn):
        self._tests.append(fn)
        return fn

    def __iter__(self):
        return iter(self._tests)

    def __len__(self):
        return len(self._tests)

    def testcase(self, name):
        """Build a TestCase whose methods are the registered functions.

        Call it at the bottom of the module, after everything is registered —
        a registry read at import time would otherwise be empty and discovery
        would go back to reporting zero.
        """
        methods = {}
        for fn in self._tests:
            def method(self, _fn=fn):
                _fn()

            method.__doc__ = fn.__doc__
            methods[f"test_{fn.__name__}"] = method

        # Without this the class reports its module as `testkit`, because that
        # is where type() was called — so a failure names this file instead of
        # the one holding the test that broke.
        if self._tests:
            methods["__module__"] = self._tests[0].__module__

        return type(name, (unittest.TestCase,), methods)

    def main(self):
        """Run everything, print a line per test, exit non-zero on failure."""
        failures = 0
        for fn in self._tests:
            try:
                fn()
                print(f"  ok  {fn.__name__}")
            except AssertionError as exc:
                failures += 1
                print(f"  FAIL {fn.__name__}\n       {exc}")
        print(f"\n{len(self._tests) - failures}/{len(self._tests)} passed")
        sys.exit(1 if failures else 0)
