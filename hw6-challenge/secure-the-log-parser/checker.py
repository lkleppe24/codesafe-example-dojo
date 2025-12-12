

import unittest
import sys
sys.path.append("/challenge")

import json
import modify_me

class TestLogParser(unittest.TestCase):
    def test_basic_parsing(self):
        parser = modify_me.LogParser()
        lines = [
            "2024-03-05 12:01:15 | INFO | User logged in",
            "2024-03-05 12:02:17 | WARN | Disk almost full"
        ]
        parser.extract_events(lines)
        self.assertEquals(len(parser.events), 2)

    def test_rejected_malicious(self):
        parser = modify_me.LogParser()
        lines = [
            "2024-03-05 12:01:15 | INFO | Hello; rm -rf /",
            "2024-03-05 12:02:17 | WARN | Safe message"
        ]
        parser.extract_events(lines)
        self.assertEquals(len(parser.rejected), 1)
        self.assertEquals(len(parser.events), 1)

    def test_strict_malicious_detection(self):
        parser = modify_me.LogParser()
        lines = [
            "2024-03-05 12:01:15 | INFO | `uname -a`",
            "2024-03-05 12:01:15 | INFO | Hello | world",
            "2024-03-05 12:01:15 | INFO | $(ls)"
        ]
        parser.extract_events(lines)

        # all three should be rejected by hardened detection
        self.assertEquals(len(parser.rejected), 3)

    def test_no_shell_execution(self):
        parser = modify_me.LogParser()
        parser.extract_events([
            "2024-03-05 12:01:15 | INFO | User logged in"
        ])

        output = parser.run_external_tool("User logged in")
        # output should NOT contain newlines or shell output side effects
        self.assertEquals(output, "User logged in")

    def test_summary(self):
        parser = modify_me.LogParser()
        parser.extract_events([
            "2024-03-05 12:01:15 | INFO | Good",
            "2024-03-05 12:01:15 | INFO | Bad; echo hacking"
        ])
        summary = json.loads(parser.summary())
        self.assertEquals(summary["accepted"], 1)
        self.assertEquals(summary["rejected"], 1)

def run_tests(test_case):
    case = unittest.TestLoader().loadTestsFromTestCase(test_case)
    result = unittest.TestResult()
    case(result)
    if result.wasSuccessful():
        print("{0}/{0} tests passed!".format(result.testsRun))
        return True
    
    else:
        print("{0}/{1} tests failed!".format(len(result.failures), result.testsRun))
        for test, err in result.failures + result.errors:
            print("===================")
            print(test)
            print(err)
        
        print("===================")
        return False

if run_tests(TestLogParser):
    print("All tests pass! Reading and displaying flag...")
    with open("/flag") as f:
        print(f.read())
else:
    print("Some tests fail. Please review the test cases and errors, then try again.")