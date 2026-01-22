![Status](https://img.shields.io/badge/status-production--ready-brightgreen)
![Shell](https://img.shields.io/badge/shell-bash-blue)
![Engine](https://img.shields.io/badge/engine-python%203-yellow)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey)

# 🔍 Zertifikats-Audit Tool

Ein **produktreifes, CI‑taugliches Zertifikats‑Audit‑Tool** für Linux‑Systeme, das **Datei‑Zertifikate** und **Live‑TLS‑Services** zuverlässig analysiert, Risiken sichtbar macht und klare Exit‑Codes für Automatisierung liefert.

> Entwickelt für Ops, Security Engineers und SREs, die Zertifikatsprobleme **finden wollen, bevor sie weh tun**.

---

## ✨ Features

* 📁 **Scan von Zertifikatsdateien** (PEM / CRT / CER / DER)
* 🏛️ **Erkennung von CA‑Bundles & Chains**
* ⏳ **Ablauf‑Analyse** (abgelaufen / bald ablaufend)
* 🌐 **Live‑TLS‑Checks** für typische Services (HTTPS, SMTP, DBs, LDAP …)
* 📊 **Strukturierter JSON‑Report** für Weiterverarbeitung
* 🖥️ **Menschenlesbarer Terminal‑Report** mit Farben & Icons
* 🧠 **Robuste Fehlerbehandlung** & Timeouts

---

## 🧱 Architektur

```text
┌──────────────┐        ┌──────────────────────────┐
│ Bash Wrapper │ ─────▶ │ Python Certificate Engine │
│              │        │ (OpenSSL‑basiert)         │
└──────────────┘        └──────────────────────────┘
        │                         │
        ▼                         ▼
  CLI‑UX / Logs            JSON‑Report
  Exit‑Codes               Zertifikats‑Details
```

* **Bash**: CLI, UX, Parameter, Exit‑Codes
* **Python**: Zertifikats‑Parsing, OpenSSL‑Analyse, TLS‑Checks

👉 Bewusst getrennt für Wartbarkeit, Testbarkeit und Stabilität.

---

## 🚀 Installation

### Voraussetzungen

* Linux (getestet mit Debian/Ubuntu)
* `bash`
* `openssl`
* `python3`

> Optional, aber empfohlen:
>
> * `jq` für schönere Report‑Ausgabe

### Recht setzen

```bash
chmod +x cert_audit.sh
```

Keine weiteren Abhängigkeiten. Kein Build. Kein Bullshit.

---

## ▶️ Verwendung

### Standard‑Audit (Dateien + Live‑Services)

```bash
./cert_audit.sh
```

### Nur Zertifikatsdateien prüfen

```bash
./cert_audit.sh --scan files
```

### Nur Live‑TLS‑Services prüfen

```bash
./cert_audit.sh --scan live
```

### Ausführliche Ausgabe

```bash
./cert_audit.sh --verbose
```

### Report erneut anzeigen (Read‑Only‑Modus)

```bash
./cert_audit.sh --report /path/to/cert_report.json
```

### Ausgabe‑Verzeichnis festlegen

```bash
./cert_audit.sh --output ~/cert-audits
```

### Warnungen ohne Fehlercode

```bash
./cert_audit.sh --warn-only
```

---

## 📊 Report‑Format (JSON)

Der JSON‑Report ist **maschinenlesbar & stabil** aufgebaut:

```json
{
  "timestamp": "2026-01-22T12:34:56Z",
  "scan_mode": "all",
  "summary": {
    "total_files": 128,
    "expired_certs": 2,
    "expiring_soon_certs": 5
  },
  "files": [
    {
      "filename": "server.pem",
      "path": "/etc/ssl/certs/server.pem",
      "days_left": 12,
      "expired": false,
      "expiring_soon": true
    }
  ],
  "live_tls": [
    {
      "service": "HTTPS",
      "endpoint": "localhost:443",
      "tls_supported": true,
      "protocol": "TLSv1.2",
      "cipher": "ECDHE-RSA-AES256-GCM-SHA384"
    }
  ]
}
```

Ideal für:

* Compliance‑Checks
* GitHub Actions
* Monitoring‑Pipelines

---

## 🚦 Exit‑Codes (CI/CD‑ready)

| Code | Bedeutung                          |
| ---: | ---------------------------------- |
|    0 | ✅ Alles OK                         |
|    2 | ❌ Abgelaufene Zertifikate gefunden |
|    3 | ⚠️ Report/Analysefehler            |

Mit `--warn-only` wird **immer 0** zurückgegeben.

---

## 🔐 Sicherheits‑Philosophie

* **Keine Netzwerk‑Scans nach außen**
* **Keine Änderungen am System**
* **Keine Zertifikate werden übertragen**
* Alles lokal, alles nachvollziehbar

Dieses Tool ist **Audit‑only** – nicht invasiv, nicht gefährlich.

---

## 🧪 Typische Use‑Cases

* 🧯 Präventive Wartung von Servern
* 🛡️ Security‑Audits
* 📋 Compliance‑Nachweise
* 😴 Ruhiger schlafen, weil Zertifikate nicht überraschen

---

## 🛠️ Mögliche Erweiterungen

* Konfigurierbare Ablauf‑Schwellen
* Service‑Definition via YAML
* GitHub Action

---

## 🧠 Fazit

> **Zertifikate sind langweilig – bis sie ablaufen.**

Dieses Tool sorgt dafür, dass das **nicht im Produktivbetrieb passiert**.

Wenn du es einsetzt und es dir einmal Ärger erspart:
👉 Mission erfüllt.

---

## Lizenz

MIT
