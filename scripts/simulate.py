#!/usr/bin/env python3
"""
NSL-KDD Simulator — sendet Datensätze zeilenweise als JSON an Logstash (TCP 5044).
Verwendung:
  python3 simulate.py                   # alle Trainingsdaten
  python3 simulate.py --file test       # Testdaten
  python3 simulate.py --category DoS   # nur DoS-Einträge
  python3 simulate.py --limit 1000     # max. 1000 Datensätze
"""

import socket
import json
import time
import argparse
import sys
from pathlib import Path

COLUMNS = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty"
]

DOS_LABELS   = {"neptune","smurf","pod","teardrop","back","land","warezclient","processtable","udpstorm"}
PROBE_LABELS = {"satan","ipsweep","nmap","portsweep","mscan","saint"}
R2L_LABELS   = {"guess_passwd","ftp_write","imap","phf","multihop","warezmaster","spy","xlock","xsnoop","snmpguess","snmpgetattack","httptunnel","sendmail","named"}
U2R_LABELS   = {"buffer_overflow","loadmodule","perl","rootkit","xterm","ps","sqlattack"}

def get_category(label):
    label = label.strip().lower()
    if label == "normal":      return "normal"
    if label in DOS_LABELS:    return "DoS"
    if label in PROBE_LABELS:  return "Probe"
    if label in R2L_LABELS:    return "R2L"
    if label in U2R_LABELS:    return "U2R"
    return "unknown"

def parse_args():
    parser = argparse.ArgumentParser(description="NSL-KDD Simulator")
    parser.add_argument("--host",     default="127.0.0.1")
    parser.add_argument("--port",     type=int, default=5044)
    parser.add_argument("--file",     choices=["train","test"], default="train")
    parser.add_argument("--category", choices=["normal","DoS","Probe","R2L","U2R","all"], default="all")
    parser.add_argument("--limit",    type=int, default=None)
    parser.add_argument("--delay",    type=float, default=0.01)
    return parser.parse_args()

def main():
    args = parse_args()
    base = Path(__file__).parent.parent / "data" / "nslkdd"
    filename = "KDDTrain+.txt" if args.file == "train" else "KDDTest+.txt"
    filepath = base / filename

    if not filepath.exists():
        print(f"Fehler: Datei nicht gefunden: {filepath}", file=sys.stderr)
        sys.exit(1)

    print(f"Verbinde mit Logstash {args.host}:{args.port} ...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.host, args.port))
    print("Verbindung hergestellt.")

    sent = 0
    skipped = 0

    with open(filepath, "r") as f:
        for line in f:
            if args.limit and sent >= args.limit:
                break
            parts = line.strip().split(",")
            if len(parts) < len(COLUMNS):
                skipped += 1
                continue
            record = dict(zip(COLUMNS, parts))
            category = get_category(record["label"])
            if args.category != "all" and category != args.category:
                continue
            record["attack_category"] = category
            record["dataset"] = args.file   # <-- neu: train oder test
            msg = json.dumps(record) + "\n"
            sock.sendall(msg.encode("utf-8"))
            sent += 1
            if sent % 500 == 0:
                print(f"  {sent} Datensätze gesendet ...")
            time.sleep(args.delay)

    sock.close()
    print(f"\nFertig: {sent} Datensätze gesendet, {skipped} übersprungen.")

if __name__ == "__main__":
    main()
