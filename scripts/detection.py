#!/usr/bin/env python3
"""
SIEM Detection Engine — regelbasierte Angriffserkennung via Elasticsearch Queries.
Erkennt Angriffskategorien anhand von Netzwerkfeatures (ohne Label-Feld).
Prueft alle 60 Sekunden und generiert Alerts bei Treffern.
"""

import requests
import time
from datetime import datetime, timezone

ES_HOST = "http://localhost:9200"
INDEX = "siem-nslkdd-*"  # Alle Daten – kein Kategorie-Index als Hint

# Feature-basierte Detection Rules (NSL-KDD Felder)
RULES = [
    {
        "id": "rule-dos",
        "name": "DoS-Angriff erkannt",
        "category": "dos",
        "description": (
            "Erkennt DoS-Angriffe: TCP SYN-Flood (flag=S0 oder serror_rate ≥ 0.5), "
            "ICMP-Flood (src_bytes ≥ 500), fragmentierte Pakete (wrong_fragment ≥ 1), "
            "oder Null-Byte-Verbindungen (src_bytes=0, dst_bytes=0, protocol=tcp)."
        ),
        "severity": "HIGH",
        "query": {
            "bool": {
                "should": [
                    # SYN-Flood: flag S0 + gleicher Dienst (neptune-typisch)
                    # same_srv_rate ≥ 0.9 schließt Port-Scans aus
                    {
                        "bool": {
                            "must": [
                                {"term": {"flag.keyword": "S0"}},
                                {"range": {"same_srv_rate": {"gte": 0.9}}},
                            ]
                        }
                    },
                    # TCP SYN-Flood mit hoher Fehlerrate (niedrigere Schwelle)
                    {
                        "bool": {
                            "must": [
                                {"term": {"protocol_type.keyword": "tcp"}},
                                {"range": {"serror_rate": {"gte": 0.5}}},
                                {"range": {"count": {"gte": 10}}},
                            ]
                        }
                    },
                    # ICMP-Flood (smurf) — src_bytes ≥ 500
                    {
                        "bool": {
                            "must": [
                                {"term": {"protocol_type.keyword": "icmp"}},
                                {"range": {"src_bytes": {"gte": 500}}},
                            ]
                        }
                    },
                    # Fragmentierungsangriffe (teardrop/pod)
                    {"range": {"wrong_fragment": {"gte": 1}}},
                    # Null-Byte TCP (land, back)
                    {
                        "bool": {
                            "must": [
                                {"term": {"protocol_type.keyword": "tcp"}},
                                {"term": {"src_bytes": 0}},
                                {"term": {"dst_bytes": 0}},
                            ],
                            "must_not": [
                                {"term": {"flag.keyword": "SF"}},
                            ],
                        }
                    },
                ],
                "minimum_should_match": 1,
            }
        },
    },
    {
        "id": "rule-probe",
        "name": "Netzwerk-Probe erkannt",
        "category": "probe",
        "description": (
            "Erkennt Port-Scanning: hohe Dienst-Diversität (diff_srv_rate ≥ 0.3) "
            "oder viele Ziel-Hosts (dst_host_count ≥ 20), "
            "oder hohe Host-Diversität pro Dienst (srv_diff_host_rate ≥ 0.3)."
        ),
        "severity": "MEDIUM",
        "query": {
            "bool": {
                "should": [
                    # Viele verschiedene Dienste auf vielen Hosts (ipsweep/satan) — gesenkte Schwellen
                    {
                        "bool": {
                            "must": [
                                {"range": {"diff_srv_rate": {"gte": 0.3}}},
                                {"range": {"dst_host_count": {"gte": 20}}},
                            ]
                        }
                    },
                    # Viele verschiedene Hosts pro Dienst (nmap-artig) — gesenkte Schwellen
                    {
                        "bool": {
                            "must": [
                                {"range": {"srv_diff_host_rate": {"gte": 0.3}}},
                                {"range": {"count": {"gte": 10}}},
                            ]
                        }
                    },
                    # Hohe dst_host_diff_srv_rate (mscan/saint)
                    {"range": {"dst_host_diff_srv_rate": {"gte": 0.3}}},
                ],
                "minimum_should_match": 1,
            }
        },
    },
    {
        "id": "rule-r2l",
        "name": "Remote-to-Local Angriff erkannt",
        "category": "r2l",
        "description": (
            "Erkennt Fernzugriffsversuche: fehlgeschlagene Logins, "
            "nicht-authentifizierte Verbindungen auf sensiblen Diensten, "
            "oder Gastlogins. Schließt DoS-ähnliche Verbindungen (count ≥ 50) aus."
        ),
        "severity": "HIGH",
        "query": {
            "bool": {
                # DoS-Indikatoren global ausschließen (processtable, neptune etc.)
                "must_not": [
                    {"range": {"count": {"gte": 50}}},
                    {"term": {"flag.keyword": "S0"}},
                ],
                "should": [
                    # Fehlgeschlagene Login-Versuche (guess_passwd)
                    {"range": {"num_failed_logins": {"gte": 1}}},
                    # Nicht eingeloggt, aber Daten auf sensiblen Diensten (ftp_write)
                    {
                        "bool": {
                            "must": [
                                {"term": {"logged_in": 0}},
                                {"range": {"dst_bytes": {"gte": 1}}},
                                {
                                    "terms": {
                                        "service.keyword": [
                                            "ftp", "ftp_data", "ssh",
                                            "telnet", "smtp",
                                        ]
                                    }
                                },
                            ]
                        }
                    },
                    # Gast-Login
                    {"term": {"is_guest_login": 1}},
                ],
                "minimum_should_match": 1,
            }
        },
    },
    {
        "id": "rule-u2r",
        "name": "Privilege Escalation erkannt",
        "category": "u2r",
        "description": (
            "Erkennt User-to-Root Angriffe: Root-Shell (root_shell=1), "
            "Root-Prozesse (num_root ≥ 1), su-Versuche (su_attempted=1), "
            "oder Shell-Spawning (num_shells ≥ 1)."
        ),
        "severity": "CRITICAL",
        "query": {
            "bool": {
                "should": [
                    {"term": {"root_shell": 1}},
                    {"range": {"num_root": {"gte": 1}}},
                    {"term": {"su_attempted": 1}},
                    {"range": {"num_shells": {"gte": 1}}},
                ],
                "minimum_should_match": 1,
            }
        },
    },
]


def query_features(rule, minutes=60):
    """Sucht Dokumente anhand von Feature-Bedingungen (kein Label-Feld)."""
    query = {
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": f"now-{minutes}m",
                                "lte": "now",
                            }
                        }
                    },
                    rule["query"],
                ]
            }
        },
        "aggs": {
            "by_protocol": {"terms": {"field": "protocol_type.keyword", "size": 5}},
            "by_service":  {"terms": {"field": "service.keyword",       "size": 5}},
            "avg_src_bytes": {"avg": {"field": "src_bytes"}},
            "avg_count":     {"avg": {"field": "count"}},
        },
        "size": 0,
    }
    try:
        r = requests.post(f"{ES_HOST}/{INDEX}/_search", json=query, timeout=5)
        data = r.json()
        count = data.get("hits", {}).get("total", {}).get("value", 0)
        aggs  = data.get("aggregations", {})
        return count, aggs
    except Exception as e:
        print(f"  Fehler: {e}")
        return 0, {}


def save_alert(rule, count, aggs):
    """Speichert Alert in Elasticsearch."""
    protocols = [b["key"] for b in aggs.get("by_protocol", {}).get("buckets", [])[:3]]
    services  = [b["key"] for b in aggs.get("by_service",  {}).get("buckets", [])[:3]]
    avg_src   = aggs.get("avg_src_bytes", {}).get("value")
    avg_cnt   = aggs.get("avg_count",     {}).get("value")

    alert = {
        "@timestamp":            datetime.now(timezone.utc).isoformat(),
        "rule_id":               rule["id"],
        "rule_name":             rule["name"],
        "category":              rule["category"],
        "severity":              rule["severity"],
        "event_count":           count,
        "detection_method":      "feature_based",
        "top_protocols":         protocols,
        "top_services":          services,
        "avg_src_bytes":         round(avg_src, 2) if avg_src is not None else None,
        "avg_connection_count":  round(avg_cnt, 2) if avg_cnt is not None else None,
        "message": f"{rule['name']}: {count} Ereignisse erkannt (feature-basiert)",
    }
    try:
        r = requests.post(f"{ES_HOST}/siem-alerts/_doc", json=alert, timeout=5)
        return r.status_code == 201
    except Exception as e:
        print(f"  Fehler beim Speichern: {e}")
        return False


def run_detection():
    print(f"\n{'='*60}")
    print(f"Detection Run: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Methode: Feature-basierte Erkennung (ohne Label-Feld)")
    print(f"{'='*60}")

    alerts_generated = 0
    for rule in RULES:
        count, aggs = query_features(rule)
        status = "🔴 ALERT" if count > 0 else "✅ OK"
        print(f"{status} [{rule['severity']:8}] {rule['name']}: {count} Treffer")

        if count > 0:
            protocols = [b["key"] for b in aggs.get("by_protocol", {}).get("buckets", [])[:3]]
            services  = [b["key"] for b in aggs.get("by_service",  {}).get("buckets", [])[:3]]
            if protocols: print(f"         Protokolle: {', '.join(protocols)}")
            if services:  print(f"         Dienste:    {', '.join(services)}")
            avg_src = aggs.get("avg_src_bytes", {}).get("value")
            if avg_src is not None: print(f"         Ø src_bytes: {avg_src:.0f}")
            if save_alert(rule, count, aggs):
                alerts_generated += 1

    print(f"\nAlerts generiert: {alerts_generated}")
    return alerts_generated


if __name__ == "__main__":
    print("SIEM Detection Engine gestartet")
    print("Methode: Feature-basierte Erkennung (ohne Label-Feld)")
    print("Pruefe alle 60 Sekunden...")
    print("Abbruch mit Ctrl+C\n")

    run_detection()

    while True:
        time.sleep(60)
        run_detection()