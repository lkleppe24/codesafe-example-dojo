Your team at SafeSight Analytics, a security-focused data processing startup, relies on an internal tool called LogParserX. It ingests log files uploaded by field engineers and extracts events for further analysis.

Recently, the security team discovered that LogParserX is vulnerable:
its naïve parsing logic allows attackers to inject malicious commands simply by embedding shell syntax into log fields. This could lead to catastrophic consequences—execution of unauthorized commands on the server during log processing.

As the new software engineer on the team, you’ve been tasked with:

Identifying and patching the vulnerable code that performs unsafe shell calls.

Hardening the parser so that user-supplied data can never result in shell execution.

Preserving all existing functionality so that legitimate logs still process correctly.

You’ve been given the starter source code for LogParserX, which contains the vulnerability.
Your job is to fix it.

Your patch must ensure:

No shell commands run using unsanitized input.

All events are parsed correctly.

Log fields containing suspicious characters (;, |, &, $, backticks, etc.) are rejected and logged safely.

All provided test cases pass.

To complete this challenge, simply modify `LogParser` in `modify_me.py` to perform as specified above. After doing that, open up a terminal in the VSCode workspace and run the following commands:

```
$ cd /challenge
$ ./checker
```
