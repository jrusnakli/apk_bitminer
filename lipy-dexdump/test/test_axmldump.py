"""Tests for lipy-dexdump."""
import os
import sys

from linkedin.dexdump.parsing import AXMLParser, main_axml

RESOURCE_DIR = os.path.join(os.path.dirname(__file__), "resources")
TEST_APK = os.path.join(RESOURCE_DIR, "MDCTest-debug.apk")

EXPECTED_XML = str("""<manifest  package='com.linkedin.mdctest.test' platformBuildVersionCode='25' platformBuildVersionName='7.1.1'>
  <uses-sdk  minSdkVersion='resourceID 0xf' targetSdkVersion='resourceID 0x19'>
  
</uses-sdk>
  <instrumentation  label='Tests for com.linkedin.mdctest' name='android.support.test.runner.AndroidJUnitRunner' targetPackage='com.linkedin.mdctest' handleProfiling='resourceID 0x0' functionalTest='resourceID 0x0'>
  
</instrumentation>
  <application  debuggable>
  <uses-library  name='android.test.runner'>
  
</uses-library>
</application>
</manifest>""")  # noqa


class TestAXMLParsing(object):

    def test_apk_parsing(self):
        xml = str(AXMLParser.parse(TEST_APK))
        assert xml == EXPECTED_XML

    def test_main(self, monkeypatch):
        argv = sys.argv

        def write_(text):
            assert text == EXPECTED_XML

        try:
            sys.argv = [argv[0], TEST_APK]
            monkeypatch.setattr("sys.stdout.write", write_)
            main_axml()
        finally:
            sys.argv = argv
