# Security Log Analyzer

This program is a Python-based tool that analyzes SSH authentication logs to identify failed login attempts and potentially suspicious activity.

The analyzer tracks failed login attempts by IP address and username, flags IP addresses that exceed a configurable failure threshold, and generates a text report summarizing its findings.

## Features

- **Failed Login Detection:** Identifies failed SSH authentication attempts in log files.
- **IP Address Tracking:** Counts failed login attempts originating from each valid IP address.
- **Username Tracking:** Tracks failed login attempts associated with individual usernames.
- **Suspicious Activity Detection:** Flags IP addresses with three or more failed login attempts by default.
- **Input Validation:** Skips invalid IP addresses and handles malformed log entries.
- **Report Generation:** Creates a text report containing login statistics, suspicious activity warnings, and summary totals.

## Requirements

- Python 3
- No external dependencies required

## How to Run the Analyzer

1. Open a terminal in the project directory.
2. Run the following command with your desired SSH authentication log file:                   

```bash
python main.py your_log_file.log
```

3. The analyzer displays failed login statistics and suspicious activity warnings in the terminal.
4. A report named `security_report.txt` is generated in the current working directory.

## Trying the Sample Log

A sample authentication log is included for demonstration purposes.

To try the analyzer, run the command: 
                 
```bash
python main.py sample_auth.log
```

This allows users to explore the analyzer's functionality without providing their own log file.

## Example Output

When analyzing `sample_auth.log`, the analyzer produces the following terminal output:

```text
Failed login attempts:
 - 192.0.2.10: 4 failed attempts
 - 203.0.113.20: 3 failed attempts
 - 198.51.100.5: 1 failed attempt

Failed login attempts by username:
 - admin: 5 failed attempts
 - gilgamesh: 3 failed attempts
Total failed login attempts: 8
WARNING: Suspicious login activity detected from 192.0.2.10
WARNING: Suspicious login activity detected from 203.0.113.20
Total suspicious IP addresses: 2
```

The analyzer also generates a `security_report.txt` file containing the analysis results.

## Testing

The project includes automated unit tests using Python's built-in unittest framework.

To run the tests:

```bash
python -m unittest test_main.py -v
```

## Limitations

- Designed to analyze SSH authentication logs containing "Failed password" entries.
- Log entries using different formats may not be recognized.
- Suspicious activity is identified using a configurable threshold of failed login attempts per IP address, rather than time-based analysis.
- The analyzer identifies potentially suspicious activity but does not confirm whether an actual attack    occurred.
