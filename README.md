# SIEM-System auf Basis des ELK-Stacks

Prototypische Implementierung eines Security Information and Event Management (SIEM)-Systems zur regelbasierten Erkennung von Netzwerkangriffen. Entwickelt im Rahmen einer wissenschaftlichen Arbeit an der Hochschule Fulda (Fachbereich Angewandte Informatik).

## Überblick

Das System erfasst, normalisiert und speichert Netzwerkereignisse auf Basis des [NSL-KDD-Datensatzes](https://www.unb.ca/cic/datasets/nsl.html) und erkennt Angriffe der Kategorien **DoS**, **Probe**, **R2L** und **U2R** anhand feature-basierter Elasticsearch-Regeln — ohne Verwendung des Ground-Truth-Felds `label`.

## Systemarchitektur

```
NSL-KDD-Datensatz → simulate.py → Logstash (Port 5044) → Elasticsearch → Kibana
                                                                ↑
                                                         detection.py (alle 60s)
                                                                ↓
                                                         siem-alerts Index
```

## Voraussetzungen

- Docker Desktop ≥ 28.5
- Docker Compose ≥ 2.40
- Python 3.9+
- NSL-KDD-Datensatz: `KDDTrain+.txt` und `KDDTest+.txt` im Ordner `data/`

## Installation

```bash
# Repository klonen
git clone https://github.com/dein-name/siem-elk.git
cd siem-elk

# ELK-Stack starten
docker compose up -d

# Warten bis Elasticsearch erreichbar ist (~30s)
curl -s http://localhost:9200/_cluster/health | python3 -m json.tool
```

## Verwendung

### 1. Trainingsdaten einspielen
```bash
python3 scripts/simulate.py --file data/KDDTrain+.txt --index siem-nslkdd --delay 0.01
```

### 2. Testdaten einspielen
```bash
python3 scripts/simulate.py --file data/KDDTest+.txt --index siem-test --delay 0.01
```

### 3. Detection Engine starten
```bash
python3 scripts/detection.py
```
Prüft alle 60 Sekunden auf Angriffe und schreibt Alerts in den Index `siem-alerts`.

### 4. Evaluation ausführen
```bash
python3 scripts/eval.py
```
Berechnet TPR, FPR, Precision und F1-Score je Angriffskategorie gegen den Testdatensatz.

## Evaluationsergebnisse (NSL-KDD Testdatensatz, 22.544 Datensätze)

| Kategorie | GT     | TP    | FP    | TPR   | FPR   | F1    |
|-----------|--------|-------|-------|-------|-------|-------|
| DoS       | 7.458  | 5.628 | 1.623 | 75,5% | 10,8% | 0,765 |
| Probe     | 2.421  | 1.623 |   899 | 67,0% |  4,5% | 0,657 |
| R2L       | 2.754  |   977 |   923 | 33,9% |  4,7% | 0,408 |
| U2R       |   200  |    37 |    40 | 55,2% |  0,2% | 0,514 |
| **Ø**     |        |       |       | **57,9%** | **5,0%** | **0,586** |

## Technische Umgebung

| Komponente       | Version |
|------------------|---------|
| Elasticsearch    | 8.17.0  |
| Logstash         | 8.17.0  |
| Kibana           | 8.17.0  |
| Docker Desktop   | 28.5.1  |
| Python           | 3.13.3  |

## Projektstruktur

```
siem-elk/
├── docker-compose.yml        # ELK-Stack Konfiguration
├── logstash/
│   └── pipeline/
│       └── nslkdd.conf       # Logstash-Pipeline (Input, Filter, Output)
├── scripts/
│   ├── simulate.py           # Datensimulator (NSL-KDD → Logstash)
│   ├── detection.py          # Detection Engine (feature-basiert)
│   └── eval.py               # Evaluation (TPR/FPR/F1 gegen Ground Truth)
└── data/                     # NSL-KDD Datensätze (nicht im Repo enthalten)
    ├── KDDTrain+.txt
    └── KDDTest+.txt
```

## Wissenschaftliche Arbeit

Eugen Hasenkampf: *Konzeption und Realisierung eines SIEM-Systems auf Basis des ELK-Stacks zur regelbasierten Erkennung von Netzwerkangriffen*. Hochschule Fulda, Fachbereich Angewandte Informatik, 2026.
