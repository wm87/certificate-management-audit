#!/usr/bin/env bash
set -euo pipefail

##############################
# Farben
##############################
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
MAGENTA="\033[0;35m"
CYAN="\033[0;36m"
BOLD="\033[1m"
RESET="\033[0m"

##############################
# Parameter
##############################
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DEFAULT_BASE_DIR="/tmp/cert_audit_$TIMESTAMP"
BASE_DIR="$DEFAULT_BASE_DIR"
JSON_REPORT="$BASE_DIR/cert_report.json"

WARN_ONLY=false
KEEP_FILES=false
VERBOSE=false
SCAN_MODE="all"
REPORT_ONLY=false # Neuer Modus: Nur Report anzeigen

print_usage() {
	cat <<EOF
${BOLD}Zertifikats-Audit Tool${RESET}

${BOLD}Verwendung:${RESET}
  $0 [OPTIONEN]

${BOLD}Optionen:${RESET}
  --warn-only     Nur Warnungen, Exit-Code immer 0
  --keep-files    Temporäre Dateien behalten (zeigt Pfad an)
  --verbose       Ausführliche Ausgabe
  --scan MODE     Scan-Modus: files, live, all (Standard: all)
  --report FILE   Zeige vorhandenen Report an
  --output DIR    Ausgabeverzeichnis (Standard: /tmp/cert_audit_<timestamp>)
  -h, --help      Diese Hilfe anzeigen

${BOLD}Beispiele:${RESET}
  $0                         # Kompletter Audit
  $0 --verbose              # Mit detaillierter Ausgabe
  $0 --scan files           # Nur Dateien prüfen
  $0 --report /path/to/report.json  # Vorhandenen Report anzeigen
  $0 --output ~/audits      # Report in spezifisches Verzeichnis speichern
  $0 --keep-files           # Dateien behalten und Pfad anzeigen
EOF
}

while [[ $# -gt 0 ]]; do
	case $1 in
	--warn-only) WARN_ONLY=true ;;
	--keep-files) KEEP_FILES=true ;;
	--verbose) VERBOSE=true ;;
	--scan)
		SCAN_MODE="$2"
		shift
		;;
	--report)
		REPORT_ONLY=true
		JSON_REPORT="$2"
		shift
		;;
	--output)
		BASE_DIR="$2"
		JSON_REPORT="$BASE_DIR/cert_report.json"
		mkdir -p "$BASE_DIR"
		shift
		;;
	-h | --help)
		print_usage
		exit 0
		;;
	*)
		echo -e "${RED}Unbekannte Option: $1${RESET}"
		exit 1
		;;
	esac
	shift
done

##############################
# Logging
##############################
log_info() { echo -e "${BLUE}[INFO]${RESET} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${RESET} $*"; }
log_error() { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
log_success() { echo -e "${GREEN}[SUCCESS]${RESET} $*"; }
log_debug() { if $VERBOSE; then echo -e "${MAGENTA}[DEBUG]${RESET} $*"; fi; }

##############################
# Cleanup - WICHTIG: Nur wenn KEEP_FILES=false
##############################
cleanup() {
	if $KEEP_FILES; then
		echo -e "\n${GREEN}${BOLD}💾 AUDIT-DATEIEN GESPEICHERT:${RESET}"
		echo -e "  📁 Verzeichnis: $BASE_DIR"
		echo -e "  📋 Report: $JSON_REPORT"
		echo -e "  🐍 Python-Skript: $BASE_DIR/analyze_certs.py"
		echo -e "\n${YELLOW}Hinweis:${RESET} Dateien werden nicht automatisch gelöscht."
	else
		# Nur im Fehlerfall löschen, nicht bei normaler Ausführung
		# Damit der Report verfügbar bleibt
		if [ -d "$BASE_DIR" ] && [ -f "$JSON_REPORT" ]; then
			# Behalte Report für spätere Verwendung
			log_debug "Report bleibt verfügbar in: $JSON_REPORT"
		fi
	fi
}
trap cleanup EXIT

##############################
# Abhängigkeiten
##############################
check_deps() {
	log_info "Prüfe Abhängigkeiten..."
	local missing_deps=()

	for dep in openssl python3; do
		if ! command -v "$dep" >/dev/null; then
			missing_deps+=("$dep")
		fi
	done

	if [ ${#missing_deps[@]} -gt 0 ]; then
		log_warn "Fehlende Abhängigkeiten: ${missing_deps[*]}"
		for dep in "${missing_deps[@]}"; do
			if command -v apt-get >/dev/null; then
				log_info "Installiere $dep mit apt-get..."
				sudo apt-get update && sudo apt-get install -y "$dep" || {
					log_error "Installation von $dep fehlgeschlagen"
					return 1
				}
			elif command -v yum >/dev/null; then
				log_info "Installiere $dep mit yum..."
				sudo yum install -y "$dep" || {
					log_error "Installation von $dep fehlgeschlagen"
					return 1
				}
			elif command -v dnf >/dev/null; then
				log_info "Installiere $dep mit dnf..."
				sudo dnf install -y "$dep" || {
					log_error "Installation von $dep fehlgeschlagen"
					return 1
				}
			else
				log_error "Paketmanager nicht gefunden. Bitte installiere manuell: ${missing_deps[*]}"
				return 1
			fi
		done
	fi

	log_success "Alle Abhängigkeiten erfüllt"
	return 0
}

##############################
# Python-Analyzer - KORRIGIERTE VERSION
##############################
create_python_analyzer() {
	cat >"$BASE_DIR/analyze_certs.py" <<'EOF'
#!/usr/bin/env python3
import json
import os
import sys
import subprocess
import ssl
import socket
from datetime import datetime, timezone
from pathlib import Path
import re

def get_certificate_info(cert_path):
    """Hole Zertifikatsinformationen mit openssl."""
    try:
        # Prüfe ob Datei existiert und lesbar ist
        if not os.path.exists(cert_path):
            return None
        if not os.access(cert_path, os.R_OK):
            return {'path': cert_path, 'filename': os.path.basename(cert_path), 'error': 'Keine Leserechte'}
        
        # Versuche, alle Zertifikate in der Datei zu lesen (kann mehrere enthalten)
        certs = []
        with open(cert_path, 'r') as f:
            content = f.read()
            
        # Trenne PEM-Zertifikate
        cert_matches = re.findall(r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', 
                                 content, re.DOTALL)
        
        if not cert_matches:
            return None
            
        for i, cert_content in enumerate(cert_matches):
            # Temporäre Datei für einzelnes Zertifikat
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as tmp:
                tmp.write(f'-----BEGIN CERTIFICATE-----\n{cert_content.strip()}\n-----END CERTIFICATE-----\n')
                tmp_path = tmp.name
            
            try:
                cmd = [
                    'openssl', 'x509',
                    '-in', tmp_path,
                    '-noout',
                    '-enddate',
                    '-subject',
                    '-issuer',
                    '-dates',
                    '-serial'
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                os.unlink(tmp_path)
                
                if result.returncode != 0:
                    continue
                
                info = {
                    'path': cert_path,
                    'filename': os.path.basename(cert_path),
                    'cert_index': i,
                    'total_certs_in_file': len(cert_matches)
                }
                
                for line in result.stdout.split('\n'):
                    if line.startswith('notAfter='):
                        info['expires'] = line.split('=', 1)[1]
                    elif line.startswith('notBefore='):
                        info['starts'] = line.split('=', 1)[1]
                    elif line.startswith('subject='):
                        info['subject'] = line.split('=', 1)[1]
                    elif line.startswith('issuer='):
                        info['issuer'] = line.split('=', 1)[1]
                    elif line.startswith('serial='):
                        info['serial'] = line.split('=', 1)[1]
                
                # Prüfe ob es sich um ein CA-Bundle handelt
                filename_lower = info['filename'].lower()
                info['is_ca_bundle'] = any(x in filename_lower for x in 
                                          ['ca', 'bundle', 'chain', 'root', 'certificates.crt'])
                
                # Berechne Tage bis zum Ablauf
                if 'expires' in info:
                    try:
                        expires_str = info['expires'].replace(' GMT', '').strip()
                        expires_date = datetime.strptime(expires_str, '%b %d %H:%M:%S %Y')
                        now = datetime.now(timezone.utc).replace(tzinfo=None)
                        days_left = (expires_date - now).days
                        
                        info['days_left'] = days_left
                        info['expired'] = days_left < 0
                        info['expiring_soon'] = 0 <= days_left < 30
                        info['expires_date'] = expires_date.isoformat()
                        
                    except Exception as e:
                        info['error'] = f"Date parsing error: {str(e)}"
                        info['days_left'] = 0
                        info['expired'] = False
                        info['expiring_soon'] = False
                
                certs.append(info)
                
            except Exception as e:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                continue
        
        # Wenn nur ein Zertifikat in der Datei ist, gebe es direkt zurück
        if len(certs) == 1:
            return certs[0]
        elif len(certs) > 1:
            # Für Bundles, finde das früheste Ablaufdatum
            earliest_expiry = min(certs, key=lambda x: x.get('days_left', 99999))
            earliest_expiry['is_bundle'] = True
            earliest_expiry['certs_in_bundle'] = len(certs)
            return earliest_expiry
        
        return None
        
    except Exception as e:
        return {'path': cert_path, 'filename': os.path.basename(cert_path), 'error': str(e)}

def check_tls_endpoint(host, port, name):
    """Prüfe einen TLS-Endpoint - KORRIGIERTE VERSION."""
    try:
        # Zuerst mit socket prüfen ob Port offen ist
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result != 0:
            return {
                'service': name,
                'endpoint': f'{host}:{port}',
                'tls_supported': False,
                'reachable': False,
                'error': 'Port nicht erreichbar'
            }
        
        # Dann mit openssl prüfen
        cmd = [
            'timeout', '3',
            'openssl', 's_client',
            '-connect', f'{host}:{port}',
            '-servername', host,
            '-tls1_2'
        ]
        
        # Korrekte Handhabung von stdin
        result = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
        
        info = {
            'service': name,
            'endpoint': f'{host}:{port}',
            'tls_supported': False,
            'reachable': True
        }
        
        if 'CONNECTED' in result.stdout or result.returncode == 0:
            info['tls_supported'] = True
            
            # Extrahiere Zertifikatsinfo
            cert_match = re.search(r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', 
                                  result.stdout, re.DOTALL)
            if cert_match:
                # Temporäre Datei für Zertifikat
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as tmp:
                    tmp.write(f'-----BEGIN CERTIFICATE-----\n{cert_match.group(1).strip()}\n-----END CERTIFICATE-----\n')
                    tmp_path = tmp.name
                
                try:
                    cmd_cert = ['openssl', 'x509', '-in', tmp_path, '-noout', '-enddate', '-subject', '-issuer']
                    cert_result = subprocess.run(cmd_cert, capture_output=True, text=True, timeout=3)
                    
                    if cert_result.returncode == 0:
                        for line in cert_result.stdout.split('\n'):
                            if line.startswith('notAfter='):
                                info['expires'] = line.split('=', 1)[1]
                            elif line.startswith('subject='):
                                info['subject'] = line.split('=', 1)[1]
                            elif line.startswith('issuer='):
                                info['issuer'] = line.split('=', 1)[1]
                    
                    os.unlink(tmp_path)
                except:
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
            
            for line in result.stdout.split('\n'):
                if 'Protocol' in line and 'TLS' in line:
                    info['protocol'] = line.split()[-1]
                elif 'Cipher' in line and ':' in line:
                    info['cipher'] = line.split(':')[1].strip()
                elif 'Verify return code:' in line:
                    info['verify_code'] = line.split(':')[1].strip()
        else:
            # Falls openssl fehlschlägt, aber Port offen war
            info['error'] = f'OpenSSL error: {result.stderr[:100]}'
        
        return info
    except subprocess.TimeoutExpired:
        return {
            'service': name,
            'endpoint': f'{host}:{port}',
            'tls_supported': False,
            'reachable': True,
            'error': 'Timeout bei TLS-Verbindung'
        }
    except Exception as e:
        return {
            'service': name,
            'endpoint': f'{host}:{port}',
            'tls_supported': False,
            'error': str(e)
        }

def scan_certificate_files():
    """Scannt System nach Zertifikatsdateien."""
    cert_dirs = [
        '/etc/ssl/certs',
        '/etc/pki/tls/certs',
        '/usr/local/share/ca-certificates',
        '/usr/share/ca-certificates',
        '/etc/ca-certificates'
    ]
    
    cert_extensions = ['.crt', '.pem', '.cer', '.der']
    
    all_certs = []
    scanned_dirs = 0
    
    for cert_dir in cert_dirs:
        if os.path.exists(cert_dir) and os.path.isdir(cert_dir):
            scanned_dirs += 1
            for root, dirs, files in os.walk(cert_dir):
                for file in files:
                    if any(file.lower().endswith(ext) for ext in cert_extensions):
                        cert_path = os.path.join(root, file)
                        all_certs.append(cert_path)
    
    return all_certs, scanned_dirs

def main():
    # Argumente
    scan_mode = sys.argv[1] if len(sys.argv) > 1 else 'all'
    output_file = sys.argv[2] if len(sys.argv) > 2 else '/tmp/cert_report.json'
    verbose = len(sys.argv) > 3 and sys.argv[3] == 'verbose'
    
    report = {
        'files': [], 
        'live_tls': [], 
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'scan_mode': scan_mode,
        'summary': {},
        'metadata': {
            'hostname': socket.gethostname(),
            'python_version': sys.version
        }
    }
    
    # Datei-Zertifikate scannen
    if scan_mode in ['files', 'all']:
        if verbose:
            print("🔍 Scanne Zertifikatsdateien...", file=sys.stderr)
        
        cert_files, scanned_dirs = scan_certificate_files()
        
        if verbose:
            print(f"  Gefundene Zertifikatsdateien: {len(cert_files)}", file=sys.stderr)
            print(f"  Durchsuchte Verzeichnisse: {scanned_dirs}", file=sys.stderr)
        
        cert_count = 0
        analyzed_count = 0
        for cert_path in cert_files:
            cert_info = get_certificate_info(cert_path)
            if cert_info:
                if 'error' not in cert_info:
                    report['files'].append(cert_info)
                    analyzed_count += 1
                cert_count += 1
                
                if verbose and cert_count % 20 == 0:
                    print(f"  Analysiert: {cert_count}/{len(cert_files)}...", file=sys.stderr)
        
        if verbose:
            print(f"  Erfolgreich analysiert: {analyzed_count}/{cert_count}", file=sys.stderr)
    
    # Live TLS-Endpoints prüfen
    if scan_mode in ['live', 'all']:
        if verbose:
            print("🌐 Prüfe TLS-Endpoints...", file=sys.stderr)
        
        endpoints = [
            ('HTTPS', 'localhost', 443),
            ('PostgreSQL', 'localhost', 5432),
            ('MySQL', 'localhost', 3306),
            ('Redis', 'localhost', 6379),
            ('LDAP', 'localhost', 636),
            ('SMTP', 'localhost', 587)
        ]
        
        for name, host, port in endpoints:
            if verbose:
                print(f"  Prüfe {name} ({host}:{port})...", file=sys.stderr)
            
            tls_info = check_tls_endpoint(host, port, name)
            report['live_tls'].append(tls_info)
    
    # Zusammenfassung erstellen
    file_count = len(report['files'])
    live_count = len(report['live_tls'])
    expired_count = sum(1 for f in report['files'] if f.get('expired', False))
    expiring_count = sum(1 for f in report['files'] if f.get('expiring_soon', False))
    ca_bundle_count = sum(1 for f in report['files'] if f.get('is_ca_bundle', False))
    
    report['summary'] = {
        'total_files': file_count,
        'total_live_services': live_count,
        'expired_certs': expired_count,
        'expiring_soon_certs': expiring_count,
        'ca_bundles': ca_bundle_count
    }
    
    # Report schreiben
    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        if verbose:
            print(f"\n✅ Analyse abgeschlossen:", file=sys.stderr)
            print(f"  📁 Zertifikatsdateien: {file_count}", file=sys.stderr)
            print(f"  🌐 Live Services: {live_count}", file=sys.stderr)
            print(f"  🏛️  CA-Bundles: {ca_bundle_count}", file=sys.stderr)
            print(f"  ❌ Abgelaufen: {expired_count}", file=sys.stderr)
            print(f"  ⚠️  Bald ablaufend: {expiring_count}", file=sys.stderr)
            print(f"  📋 Report: {output_file}", file=sys.stderr)
        
        return 0
    except Exception as e:
        print(f"❌ Fehler beim Schreiben des Reports: {e}", file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
EOF
	chmod +x "$BASE_DIR/analyze_certs.py"
}

##############################
# Report anzeigen
##############################
show_report() {
	local report_file="$1"

	[ ! -f "$report_file" ] && {
		log_error "Report nicht gefunden: $report_file"
		echo -e "${YELLOW}Verfügbare Reporte in $BASE_DIR:${RESET}"
		ls -la "$BASE_DIR/"*.json 2>/dev/null || echo "Keine Reporte gefunden"
		return 1
	}

	echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════════${RESET}"
	echo -e "${BOLD}📊 ZERTIFIKATS-AUDIT REPORT${RESET}"
	echo -e "${CYAN}══════════════════════════════════════════════════════════${RESET}\n"

	# Grundlegende Statistiken
	local summary_json
	if command -v jq >/dev/null; then
		summary_json=$(jq -r '.summary // {} | tostring' "$report_file" 2>/dev/null || echo "{}")
	else
		summary_json=$(python3 -c "
import json
try:
    with open('$report_file') as f:
        data = json.load(f)
    print(json.dumps(data.get('summary', {})))
except:
    print('{}')
" 2>/dev/null)
	fi

	# Parse die Zusammenfassung
	local file_count=0 live_count=0 expired_count=0 expiring_count=0 ca_bundle_count=0
	local scan_mode="unknown" timestamp="unknown"

	if [ -n "$summary_json" ] && [ "$summary_json" != "{}" ]; then
		if command -v jq >/dev/null; then
			file_count=$(echo "$summary_json" | jq -r '.total_files // 0')
			live_count=$(echo "$summary_json" | jq -r '.total_live_services // 0')
			expired_count=$(echo "$summary_json" | jq -r '.expired_certs // 0')
			expiring_count=$(echo "$summary_json" | jq -r '.expiring_soon_certs // 0')
			ca_bundle_count=$(echo "$summary_json" | jq -r '.ca_bundles // 0')
		else
			read -r file_count live_count expired_count expiring_count ca_bundle_count <<<$(python3 -c "
import json
try:
    summary = json.loads('''$summary_json''')
    print(
        summary.get('total_files', 0),
        summary.get('total_live_services', 0),
        summary.get('expired_certs', 0),
        summary.get('expiring_soon_certs', 0),
        summary.get('ca_bundles', 0)
    )
except:
    print('0 0 0 0 0')
" 2>/dev/null)
		fi
	fi

	# Hole zusätzliche Infos
	if command -v jq >/dev/null; then
		scan_mode=$(jq -r '.scan_mode // "all"' "$report_file" 2>/dev/null)
		timestamp=$(jq -r '.timestamp // "unknown"' "$report_file" 2>/dev/null | sed 's/T/ /' | cut -d'.' -f1)
	else
		read -r scan_mode timestamp <<<$(python3 -c "
import json
try:
    with open('$report_file') as f:
        data = json.load(f)
    scan_mode = data.get('scan_mode', 'all')
    timestamp = data.get('timestamp', 'unknown').replace('T', ' ').split('.')[0]
    print(f'{scan_mode} {timestamp}')
except:
    print('all unknown')
" 2>/dev/null)
	fi

	echo -e "${BOLD}📈 ZUSAMMENFASSUNG:${RESET}"
	echo -e "  📁 Zertifikatsdateien: $file_count"
	echo -e "  🌐 Live Services: $live_count"
	echo -e "  🏛️  CA-Bundles: $ca_bundle_count"

	if [ "$expired_count" -gt 0 ]; then
		echo -e "  ${RED}❌ Abgelaufen: $expired_count${RESET}"
	else
		echo -e "  ${GREEN}✅ Abgelaufen: $expired_count${RESET}"
	fi

	if [ "$expiring_count" -gt 0 ]; then
		echo -e "  ${YELLOW}⚠️  Bald ablaufend (<30 Tage): $expiring_count${RESET}"
	else
		echo -e "  ${GREEN}✅ Bald ablaufend: $expiring_count${RESET}"
	fi

	echo ""

	# Abgelaufene Zertifikate zeigen (erste 5)
	if [ "$expired_count" -gt 0 ]; then
		echo -e "${BOLD}${RED}❌ ABGELAUFENE ZERTIFIKATE:${RESET}"
		if command -v jq >/dev/null; then
			jq -r '
                .files[] | 
                select(.expired == true) | 
                "  ✗ " + .filename + 
                (if .is_ca_bundle then " (CA-BUNDLE)" else "" end) + 
                "\n    📅 Abgelaufen vor " + ((.days_left | tostring | gsub("-"; ""))) + " Tagen" +
                "\n    📍 " + .path + "\n"
            ' "$report_file" | head -15 2>/dev/null || python3 -c "
import json
try:
    with open('$report_file') as f:
        data = json.load(f)
    
    expired_certs = [f for f in data.get('files', []) if f.get('expired') == True]
    
    for i, cert in enumerate(expired_certs[:5]):
        filename = cert.get('filename', 'unknown')
        path = cert.get('path', 'unknown')
        days_left = cert.get('days_left', 0)
        is_ca = cert.get('is_ca_bundle', False)
        is_bundle = cert.get('is_bundle', False)
        bundle_count = cert.get('certs_in_bundle', 0)
        
        markers = []
        if is_ca: markers.append('CA-BUNDLE')
        if is_bundle: markers.append(f'Bundle ({bundle_count} Zerts)')
        marker_str = ' (' + ', '.join(markers) + ')' if markers else ''
        
        days_ago = abs(int(days_left))
        
        print(f'  ✗ {filename}{marker_str}')
        print(f'    📅 Abgelaufen vor {days_ago} Tagen')
        print(f'    📍 {path}')
        print()
    
    if len(expired_certs) > 5:
        print(f'  ... und {len(expired_certs) - 5} weitere abgelaufene Zertifikate')
        print()
except Exception as e:
    print(f'  Fehler beim Laden: {str(e)}')
    print()
" 2>/dev/null
		else
			python3 -c "
import json
try:
    with open('$report_file') as f:
        data = json.load(f)
    
    expired_certs = [f for f in data.get('files', []) if f.get('expired') == True]
    
    for i, cert in enumerate(expired_certs[:5]):
        filename = cert.get('filename', 'unknown')
        path = cert.get('path', 'unknown')
        days_left = cert.get('days_left', 0)
        is_ca = cert.get('is_ca_bundle', False)
        is_bundle = cert.get('is_bundle', False)
        bundle_count = cert.get('certs_in_bundle', 0)
        
        markers = []
        if is_ca: markers.append('CA-BUNDLE')
        if is_bundle: markers.append(f'Bundle ({bundle_count} Zerts)')
        marker_str = ' (' + ', '.join(markers) + ')' if markers else ''
        
        days_ago = abs(int(days_left))
        
        print(f'  ✗ {filename}{marker_str}')
        print(f'    📅 Abgelaufen vor {days_ago} Tagen')
        print(f'    📍 {path}')
        print()
    
    if len(expired_certs) > 5:
        print(f'  ... und {len(expired_certs) - 5} weitere abgelaufene Zertifikate')
        print()
except Exception as e:
    print(f'  Fehler beim Laden: {str(e)}')
    print()
" 2>/dev/null
		fi
	fi

	# Bald ablaufende Zertifikate zeigen
	if [ "$expiring_count" -gt 0 ]; then
		echo -e "${BOLD}${YELLOW}⚠️  BALD ABLAUFENDE ZERTIFIKATE (<30 Tage):${RESET}"
		if command -v jq >/dev/null; then
			jq -r '
                .files[] | 
                select(.expiring_soon == true and .expired != true) | 
                "  ⚠️  " + .filename + 
                (if .is_ca_bundle then " (CA-BUNDLE)" else "" end) + 
                "\n    📅 Noch " + (.days_left | tostring) + " Tage" +
                "\n    📍 " + .path + "\n"
            ' "$report_file" | head -10 2>/dev/null || python3 -c "
import json
try:
    with open('$report_file') as f:
        data = json.load(f)
    
    expiring_certs = [f for f in data.get('files', []) if f.get('expiring_soon') == True and f.get('expired') != True]
    
    for i, cert in enumerate(expiring_certs[:5]):
        filename = cert.get('filename', 'unknown')
        path = cert.get('path', 'unknown')
        days_left = cert.get('days_left', 0)
        is_ca = cert.get('is_ca_bundle', False)
        is_bundle = cert.get('is_bundle', False)
        bundle_count = cert.get('certs_in_bundle', 0)
        
        markers = []
        if is_ca: markers.append('CA-BUNDLE')
        if is_bundle: markers.append(f'Bundle ({bundle_count} Zerts)')
        marker_str = ' (' + ', '.join(markers) + ')' if markers else ''
        
        print(f'  ⚠️  {filename}{marker_str}')
        print(f'    📅 Noch {int(days_left)} Tage')
        print(f'    📍 {path}')
        print()
    
    if len(expiring_certs) > 5:
        print(f'  ... und {len(expiring_certs) - 5} weitere bald ablaufende Zertifikate')
        print()
except:
    print('  Fehler beim Laden der Daten')
    print()
" 2>/dev/null
		else
			python3 -c "
import json
try:
    with open('$report_file') as f:
        data = json.load(f)
    
    expiring_certs = [f for f in data.get('files', []) if f.get('expiring_soon') == True and f.get('expired') != True]
    
    for i, cert in enumerate(expiring_certs[:5]):
        filename = cert.get('filename', 'unknown')
        path = cert.get('path', 'unknown')
        days_left = cert.get('days_left', 0)
        is_ca = cert.get('is_ca_bundle', False)
        is_bundle = cert.get('is_bundle', False)
        bundle_count = cert.get('certs_in_bundle', 0)
        
        markers = []
        if is_ca: markers.append('CA-BUNDLE')
        if is_bundle: markers.append(f'Bundle ({bundle_count} Zerts)')
        marker_str = ' (' + ', '.join(markers) + ')' if markers else ''
        
        print(f'  ⚠️  {filename}{marker_str}')
        print(f'    📅 Noch {int(days_left)} Tage')
        print(f'    📍 {path}')
        print()
    
    if len(expiring_certs) > 5:
        print(f'  ... und {len(expiring_certs) - 5} weitere bald ablaufende Zertifikate')
        print()
except:
    print('  Fehler beim Laden der Daten')
    print()
" 2>/dev/null
		fi
	fi

	# Live Services zeigen
	if [ "$live_count" -gt 0 ]; then
		echo -e "${BOLD}🌐 LIVE SERVICES:${RESET}"
		if command -v jq >/dev/null; then
			jq -r '
                .live_tls[] | 
                (if .tls_supported then "    ✅ " else "    ❌ " end) + 
                .service + " (" + .endpoint + ")" + 
                (if .tls_supported then 
                    "\n    🌐 " + (.protocol // "unknown") + 
                    "\n    🔐 " + (.cipher // "unknown") + 
                    (if .expires then "\n    📅 " + .expires else "" end)
                else 
                    "\n    🔌 Kein TLS-Service erreichbar" + 
                    (if .error then "\n    💡 " + .error else "" end)
                end) + "\n"
            ' "$report_file" 2>/dev/null || python3 -c "
import json
try:
    with open('$report_file') as f:
        data = json.load(f)
    
    for service in data.get('live_tls', []):
        name = service.get('service', 'unknown')
        endpoint = service.get('endpoint', 'unknown')
        supported = service.get('tls_supported', False)
        error = service.get('error', '')
        
        status = '✅' if supported else '❌'
        print(f'    {status} {name} ({endpoint})')
        
        if supported:
            if 'protocol' in service:
                print(f'    🌐 {service[\"protocol\"]}')
            if 'cipher' in service:
                print(f'    🔐 {service[\"cipher\"]}')
            if 'expires' in service and service['expires']:
                print(f'    📅 {service[\"expires\"]}')
            if 'verify_code' in service:
                print(f'    ✅ Verify: {service[\"verify_code\"]}')
        else:
            print('    🔌 Kein TLS-Service erreichbar')
            if error:
                print(f'    💡 {error}')
        print()
except Exception as e:
    print(f'    Fehler beim Laden: {str(e)}')
    print()
" 2>/dev/null
		else
			python3 -c "
import json
try:
    with open('$report_file') as f:
        data = json.load(f)
    
    for service in data.get('live_tls', []):
        name = service.get('service', 'unknown')
        endpoint = service.get('endpoint', 'unknown')
        supported = service.get('tls_supported', False)
        error = service.get('error', '')
        
        status = '✅' if supported else '❌'
        print(f'    {status} {name} ({endpoint})')
        
        if supported:
            if 'protocol' in service:
                print(f'    🌐 {service[\"protocol\"]}')
            if 'cipher' in service:
                print(f'    🔐 {service[\"cipher\"]}')
            if 'expires' in service and service['expires']:
                print(f'    📅 {service[\"expires\"]}')
            if 'verify_code' in service:
                print(f'    ✅ Verify: {service[\"verify_code\"]}')
        else:
            print('    🔌 Kein TLS-Service erreichbar')
            if error:
                print(f'    💡 {error}')
        print()
except Exception as e:
    print(f'    Fehler beim Laden: {str(e)}')
    print()
" 2>/dev/null
		fi
	fi

	# Report-Info
	echo -e "${CYAN}══════════════════════════════════════════════════════════${RESET}"
	echo -e "${BOLD}📋 Report:${RESET} $report_file"
	echo -e "${BOLD}📅 Erstellt:${RESET} $timestamp"
	echo -e "${BOLD}🔍 Scan-Modus:${RESET} $scan_mode"
	echo -e "${BOLD}📊 Statistik:${RESET} $file_count Dateien, $live_count Services"
	echo -e "${CYAN}══════════════════════════════════════════════════════════${RESET}\n"

	# Zeige Pfad-Info wenn Datei existiert
	if [ -f "$report_file" ]; then
		echo -e "${GREEN}📁 Report-Datei verfügbar unter: $report_file${RESET}"
	fi
}

##############################
# Exit-Code
##############################
get_exit_code() {
	local report_file="$1"

	if [ ! -f "$report_file" ]; then
		log_error "Report-Datei nicht gefunden: $report_file"
		return 3
	fi

	local expired_count=0
	if command -v jq >/dev/null; then
		expired_count=$(jq '.summary.expired_certs // 0' "$report_file" 2>/dev/null)
	else
		expired_count=$(python3 -c "
import json
try:
    with open('$report_file') as f:
        data = json.load(f)
    expired = data.get('summary', {}).get('expired_certs', 0)
    print(expired)
except:
    print('0')
" 2>/dev/null)
	fi

	local exit_code=0

	if [[ "$expired_count" =~ ^[0-9]+$ ]]; then
		if [ "$expired_count" -gt 0 ]; then
			log_error "$expired_count abgelaufene Zertifikate gefunden"
			exit_code=2
		else
			log_success "Keine abgelaufenen Zertifikate gefunden"
			exit_code=0
		fi
	else
		log_error "Konnte abgelaufene Zertifikate nicht zählen: $expired_count"
		exit_code=3
	fi

	# Warn-only Modus überschreibt Exit-Code
	if $WARN_ONLY; then
		log_info "Warn-only Modus: Exit-Code wird auf 0 gesetzt"
		exit_code=0
	fi

	return $exit_code
}

##############################
# Hauptprogramm
##############################
main() {
	# Wenn nur Report angezeigt werden soll
	if $REPORT_ONLY; then
		if [ -f "$JSON_REPORT" ]; then
			show_report "$JSON_REPORT"
			get_exit_code "$JSON_REPORT"
			return $?
		else
			log_error "Report nicht gefunden: $JSON_REPORT"

			# Versuche Report in Standard-Verzeichnis zu finden
			local latest_report=$(find /tmp -name "cert_audit_*" -type d 2>/dev/null | sort -r | head -1)
			if [ -n "$latest_report" ] && [ -f "$latest_report/cert_report.json" ]; then
				log_info "Gefundener letzter Report: $latest_report/cert_report.json"
				read -p "Diesen Report anzeigen? (j/N): " choice
				if [[ $choice =~ ^[Jj]$ ]]; then
					JSON_REPORT="$latest_report/cert_report.json"
					show_report "$JSON_REPORT"
					get_exit_code "$JSON_REPORT"
					return $?
				fi
			fi

			return 1
		fi
	fi

	# Normaler Audit-Modus
	echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════════${RESET}"
	echo -e "${BOLD}🔍 ZERTIFIKATS-AUDIT START${RESET}"
	echo -e "${CYAN}══════════════════════════════════════════════════════════${RESET}\n"

	log_info "Starte Zertifikats-Audit..."
	log_info "Scan-Modus: $SCAN_MODE"
	log_info "Report wird gespeichert in: $JSON_REPORT"

	# Abhängigkeiten prüfen
	if ! check_deps; then
		log_error "Abhängigkeitsprüfung fehlgeschlagen"
		return 1
	fi

	# Verzeichnis erstellen
	mkdir -p "$BASE_DIR"
	log_debug "Arbeitsverzeichnis: $BASE_DIR"

	# Python-Analyzer erstellen
	create_python_analyzer
	log_debug "Python-Analyzer erstellt: $BASE_DIR/analyze_certs.py"

	# Python-Skript ausführen
	log_info "Führe Zertifikats-Analyse aus..."

	local python_args=("$SCAN_MODE" "$JSON_REPORT")
	if $VERBOSE; then
		python_args+=("verbose")
	fi

	if ! python3 "$BASE_DIR/analyze_certs.py" "${python_args[@]}"; then
		log_error "Analyse fehlgeschlagen"
		return 1
	fi

	if [ -f "$JSON_REPORT" ]; then
		log_success "Analyse erfolgreich abgeschlossen"
		echo -e "${GREEN}📁 Report gespeichert unter: $JSON_REPORT${RESET}"
	else
		log_error "Report wurde nicht erstellt"
		return 1
	fi

	# Report anzeigen
	show_report "$JSON_REPORT"

	# Exit-Code berechnen und zurückgeben
	get_exit_code "$JSON_REPORT"
	return $?
}

# Hauptprogramm ausführen
main "$@"
exit $?
