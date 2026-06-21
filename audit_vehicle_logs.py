import csv
import re
from datetime import datetime
from collections import Counter, defaultdict

VEHICLE_PATTERN: str = r"^WB\d{2}[A-Z]{2}\d{4}$"
DEVICE_PATTERN: str = r"^DEV\d{3}$"
VALID_GATES: set[str] = {"GATE-A", "GATE-B", "GATE-C", "GATE-D", "GATE-E"}
VALID_SCAN_TYPES: set[str] = {"ENTRY", "EXIT"}
ScanKeyType = tuple[str, str, str]                              # Type tuple of 3 string values used as keys for "last_scan" and "duplicate_key"
GateRecordType = list[tuple[str, datetime]]

def validate_vehicle_number(vehicle_no: str) -> bool:
    return bool(re.fullmatch(VEHICLE_PATTERN, vehicle_no))

def validate_device(device: str) -> bool:
    return bool(re.fullmatch(DEVICE_PATTERN, device))

def parse_timestamp(scan_time: str) -> datetime | None:
    try:
        return datetime.strptime(scan_time, "%d-%m-%Y %H:%M:%S")
    except ValueError:
        return None

def write_csv(filename: str, records: list[dict]):
    if not records:
        return

    fieldnames = records[0].keys()
    with open(filename, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

def generate_report(total_records: int, clean_records: list[dict], duplicate_records: list[dict], suspicious_records: list[dict], rejected_records: list[dict], vehicle_counter: Counter):
    with open("audit_summary.txt", "w", encoding="utf-8") as report:
        report.write("Vehicle Gate Log Audit Report\n")
        report.write("----------------------------------\n\n")
        report.write(f"Total Records: {total_records}\n")
        report.write(f"Clean Records: {len(clean_records)}\n")
        report.write(f"Duplicate Records: {len(duplicate_records)}\n")
        report.write(f"Suspicious Records: {len(suspicious_records)}\n")
        report.write(f"Rejected Records: {len(rejected_records)}\n\n")
        report.write("Vehicle Wise Summary\n")
        report.write("-------------------------\n")
        for vehicle, count in vehicle_counter.items():
            report.write(f"{vehicle}: {count} scans\n")

def validate_record(vehicle_no: str, gate_code: str, scan_type: str, scan_time: str, device: str) -> bool:
    if not validate_vehicle_number(vehicle_no):
        return False

    if not validate_device(device):
        return False
    if gate_code not in VALID_GATES:
        return False
    if scan_type not in VALID_SCAN_TYPES:
        return False
    if parse_timestamp(scan_time) is None:
        return False

    return True

def is_duplicate(duplicate_key: ScanKeyType, timestamp: datetime, last_scan: dict[ScanKeyType, datetime]) -> bool:
    if duplicate_key not in last_scan:
        return False

    previous_time: datetime = last_scan[duplicate_key]
    difference: float = (timestamp - previous_time).total_seconds()
    return difference <= 45

def is_suspicious(vehicle_no: str, gate_code: str, timestamp: datetime, vehicle_history: defaultdict[ str, GateRecordType]) -> bool:
    for old_gate, old_time in vehicle_history[vehicle_no]:
        same_day: bool = (old_time.date() == timestamp.date())
        different_gate: bool = (old_gate != gate_code)
        minutes: float = abs((timestamp - old_time).total_seconds()) / 60
        if (same_day and different_gate and minutes <= 30):
            return True

    return False

def process_vehicle_logs(filename: str) -> tuple:
    total_records: int = 0
    clean_records: list[dict] = []
    duplicate_records: list[dict] = []
    suspicious_records: list[dict] = []
    rejected_records: list[dict] = []
    vehicle_counter: Counter[str] = Counter()
    last_scan: dict[ScanKeyType, datetime] = {}
    vehicle_history: defaultdict[str, GateRecordType] = defaultdict(list)

    with open(filename, "r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            total_records += 1
            vehicle_no: str = row["vehicle_no"]
            gate_code: str = row["gate_code"]
            scan_type: str = row["scan_type"]
            scan_time: str = row["scan_time"]
            device: str = row["security_device"]
            vehicle_counter[vehicle_no] += 1

            if not validate_record(vehicle_no, gate_code, scan_type, scan_time, device):
                rejected_records.append(row)
                continue

            timestamp: datetime | None = parse_timestamp(scan_time)
            if timestamp is None:
                rejected_records.append(row)
                continue
            duplicate_key: ScanKeyType = (vehicle_no, scan_type, device)

            if is_duplicate(duplicate_key, timestamp, last_scan):
                duplicate_records.append(row)
                continue

            last_scan[duplicate_key] = timestamp

            if is_suspicious(vehicle_no, gate_code, timestamp, vehicle_history):
                suspicious_records.append(row)
                vehicle_history[vehicle_no].append((gate_code, timestamp))
                continue

            clean_records.append(row)
            vehicle_history[vehicle_no].append((gate_code, timestamp))

    return (total_records, clean_records, duplicate_records, suspicious_records, rejected_records, vehicle_counter)

if __name__ == "__main__":
    (total_records, clean_records, duplicate_records, suspicious_records, rejected_records, vehicle_counter) = process_vehicle_logs("raw_vehicle_logs.csv")

    write_csv("clean_records.csv", clean_records)
    write_csv("duplicate_records.csv", duplicate_records)
    write_csv("suspicious_records.csv", suspicious_records)
    write_csv("rejected_records.csv", rejected_records)

    generate_report(total_records, clean_records, duplicate_records, suspicious_records, rejected_records, vehicle_counter)
    print("Audit completed successfully.")
    print("Generated files:")
    print("- audit_summary.txt")
    print("- clean_records.csv")
    print("- duplicate_records.csv")
    print("- suspicious_records.csv")
    print("- rejected_records.csv")