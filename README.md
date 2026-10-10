#  Cybersecurity Log Analyzer

A beginner-friendly cybersecurity capstone project built with Python and Flask. This web application analyzes authentication log entries and flags repeated failed login attempts for further investigation.

## Features

* Analyze authentication log entries through a web interface
* Detect repeated failed-login attempts
* Extract and validate source IP addresses
* Set a custom detection threshold
* Display flagged IP addresses and attempt counts
* Simple, responsive dashboard
* Input size limit for basic resource protection

## Technologies Used

* Python 3
* Flask
* HTML
* CSS
* Regular expressions
* IP address validation

## Installation

Clone this repository:

```bash
git clone https://github.com/YOUR_USERNAME/cybersecurity-log-analyzer.git
cd cybersecurity-log-analyzer
```

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Run the Application

```bash
python app.py
```

Open your browser and visit:

http://127.0.0.1:5000

##  Sample Test Data

Paste these sample entries into the analyzer:

```text
Failed password for admin from 198.51.100.23 port 22 ssh2
Failed password for guest from 198.51.100.23 port 22 ssh2
Failed password for root from 198.51.100.23 port 22 ssh2
```

Set the threshold to `3`. The application should flag `198.51.100.23` with three failed attempts.

These are synthetic examples using documentation-only IP addresses.

##  Security Architecture

1. User supplies authentication log text.
2. Flask receives the submitted text.
3. The analyzer matches failed-login entries.
4. Extracted IP addresses are validated.
5. Failed attempts are counted by IP.
6. The configured threshold identifies entries for review.
7. The website displays the results.

##  Ethical Use

* Analyze only logs you own or have permission to access.
* Use synthetic or sanitized data for demonstrations.
* Never upload passwords, tokens, or confidential logs to a public repository.
* A flagged IP is not proof of malicious activity.
* This project reports findings; it does not block IP addresses.

##  Limitations

* Supports a specific failed-login log format.
* Does not detect every type of attack.
* Does not correlate events over time.
* Threshold-based alerts may produce false positives.
* The initial version does not include user authentication or a database.

##  Future Improvements

* Add downloadable JSON reports.
* Support additional authentication log formats.
* Add time-window-based detection.
* Add charts and a security dashboard.
* Add automated unit tests.
* Improve access control and deployment security.

##  Project Purpose

Developed as a hands-on cybersecurity capstone project to practise Python programming, defensive security, log analysis, and web application development.

## Author
MALINI S
