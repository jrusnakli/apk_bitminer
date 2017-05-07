"""Tests for lipy-dexdump."""
import os
from linkedin.dexdump.parsing import DexParser

RESOURCE_DIR = os.path.join(os.path.dirname(__file__), "resources")
TEST_APK = os.path.join(RESOURCE_DIR, "test.apk")


class TestDexParsing(object):

    EXPECTED_TESTS = sorted([
        "com.linkedin.mdctest.ExampleInstrumentedTest#testPassStatus",
        "com.linkedin.mdctest.ExampleInstrumentedTest#testTestButlerSetLocationMode",
        "com.linkedin.mdctest.ExampleInstrumentedTest#testZException",
        "com.linkedin.mdctest.ExampleInstrumentedTest#testTestButlerSetWifiState",
        "com.linkedin.mdctest.ExampleInstrumentedTest#testTestButlerCleanup",
        "com.linkedin.mdctest.ExampleInstrumentedTest#testTestButlerSetImmersiveModeConfirmation",
        "com.linkedin.mdctest.ExampleInstrumentedTest#testFailStatus",
        "com.linkedin.mdctest.ExampleInstrumentedTest#testTestButlerRotation",
        ])

    def test_apk_parsing(self):
        tests = DexParser.parse(TEST_APK)
        assert sorted(tests) == TestDexParsing.EXPECTED_TESTS

    def test_apk_parsing_filtered(self):
        tests = DexParser.parse(TEST_APK, ["com.linkedin.mdctest"])
        assert sorted(tests) == TestDexParsing.EXPECTED_TESTS

    def test_apk_parsing_filtered_empty_result(self):
        tests = DexParser.parse(TEST_APK, ["com.linkedin.mdctestNOT"])
        assert not tests