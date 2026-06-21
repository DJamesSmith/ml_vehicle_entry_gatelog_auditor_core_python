# Vehicle Entry Gate Log Auditor

A Core Python automation project that audits vehicle gate logs exported from security scanning devices.

The application validates vehicle records, identifies duplicate scans, detects suspicious gate switching activity, classifies records, and generates an audit report.

---

## Problem Statement

Large IT parks often receive thousands of vehicle gate logs daily from multiple security devices.

The exported logs may contain:

- Invalid vehicle registration numbers
- Invalid security device identifiers
- Duplicate scans
- Incorrect gate movements
- Malformed timestamps
- Suspicious gate switching activity

This project automates the audit process using only Python standard libraries.

---

## Features

### Vehicle Number Validation

Valid format:

```text
WB12AB1234
WB34XY7788
```

Regex Pattern:

```python
^WB\d{2}[A-Z]{2}\d{4}$
```

---

### Security Device Validation

Valid format:

```text
DEV101
DEV205
DEV999
```

Regex Pattern:

```python
^DEV\d{3}$
```

---

### Duplicate Scan Detection

A record is classified as duplicate when:

- Vehicle number is the same
- Scan type is the same
- Security device is the same
- Scan difference ≤ 45 seconds

Example:

```text
08:45:10
08:45:40
```

Difference:

```text
30 seconds
```

Result:

```text
Duplicate Record
```

---

### Suspicious Gate Switching

A record is classified as suspicious when:

- Same vehicle
- Different gates
- Same date
- Within 30 minutes

Example:

```text
10:05 -> GATE-A
10:20 -> GATE-B
```

Difference:

```text
15 minutes
```

Result:

```text
Suspicious Record
```

---

### Timestamp Validation

Valid format:

```text
DD-MM-YYYY HH:MM:SS
```

Example:

```text
10-06-2026 08:45:10
```

Invalid:

```text
INVALID_DATE
10/06/2026
2026-06-10
```

---

## Technologies Used

- Python 3
- CSV Module
- Regular Expressions (re)
- Datetime Module
- Counter
- defaultdict
- File Handling
- Exception Handling

---

## Project Structure

```text
.
├── audit_vehicle_logs.py
├── raw_vehicle_logs.csv
├── README.md
```

---

## How to Run

Clone the repository:

```bash
git clone https://github.com/DJamesSmith/ml_vehicle_entry_gatelog_auditor_core_python.git
```

Navigate to the project:

```bash
cd ml_vehicle_entry_gatelog_auditor_core_python
```

Run the script:

```bash
python audit_vehicle_logs.py
```

---

## Generated Output Files

```text
audit_summary.txt
clean_records.csv
duplicate_records.csv
suspicious_records.csv
rejected_records.csv
```

---

## Concepts Demonstrated

- CSV Processing
- File Handling
- Regular Expressions
- Datetime Calculations
- Dictionaries
- defaultdict
- Counter
- Type Hinting
- Exception Handling
- Python Automation

---

## Sample Audit Summary

```text
Vehicle Gate Log Audit Report
----------------------------------

Total Records: 9
Clean Records: 4
Duplicate Records: 1
Suspicious Records: 1
Rejected Records: 3
```

---

## Author

Dion James Smith