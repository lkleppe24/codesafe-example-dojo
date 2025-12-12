import os
import json
import re

class LogParser:
    def __init__(self):
        self.events = []
        self.rejected = []

    def load_log(self, filepath):
        """Loads a log file into memory."""
        if not os.path.exists(filepath):
            raise FileNotFoundError("Log file not found.")
        with open(filepath, "r") as f:
            return f.readlines()

    def parse_line(self, line):
        """
        Parses a single log line.
        Expected format:
        TIMESTAMP | LEVEL | MESSAGE

        Example:
        2024-03-05 12:01:15 | INFO | User logged in
        """
        if "|" not in line:
            return None

        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 3:
            return None

        timestamp, level, message = parts

        # Basic validation
        if not timestamp or not level or not message:
            return None

        return {
            "timestamp": timestamp,
            "level": level,
            "message": message
        }

    def is_malicious(self, message):
        """
        Detects suspicious content.
        This is intentionally weak in the starter code and must be improved.
        """
        # Vuln: only checks one dangerous character
        return ";" in message

    def extract_events(self, lines):
        """
        Parses all lines and stores them in self.events.
        If a line contains suspicious content, it is rejected.
        """
        for line in lines:
            parsed = self.parse_line(line)
            if not parsed:
                continue

            if self.is_malicious(parsed["message"]):
                self.rejected.append(parsed)
            else:
                self.events.append(parsed)

    def run_external_tool(self, message):
        """
        Extremely unsafe function. Used by old scripts.
        CURRENT VULNERABILITY:
          message is passed directly to the shell.
        Your job: eliminate unsafe shell execution.
        """
        cmd = f"echo {message}"
        # VULNERABLE: direct shell=True injection point
        stream = os.popen(cmd)  
        output = stream.read().strip()
        return output

    def process(self, filepath):
        """
        Loads logs, extracts events, and processes messages with external tool.
        """
        lines = self.load_log(filepath)
        self.extract_events(lines)

        processed = []
        for ev in self.events:
            processed_output = self.run_external_tool(ev["message"])
            processed.append({
                "timestamp": ev["timestamp"],
                "level": ev["level"],
                "output": processed_output
            })
        return processed

    def summary(self):
        """
        Returns a JSON summary of accepted and rejected entries.
        """
        return json.dumps({
            "accepted": len(self.events),
            "rejected": len(self.rejected)
        }, indent=2)


# Demo runner for manual tests
if __name__ == "__main__":
    parser = LogParser()
    try:
        data = parser.process("sample.log")
        print("Processed:")
        print(json.dumps(data, indent=2))
        print("Summary:")
        print(parser.summary())
    except FileNotFoundError as e:
        print("Error:", e)
