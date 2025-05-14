#!/bin/bash

# ====== Defaults ======
PORTS="1-65535"
USERNAME=""
PASSWORD=""
DOMAIN=""
IP=""

# ====== Help function ======
usage() {
  echo "Usage: $0 -i <IP> -P <ports> -u <username> -w <password> -d <domain>"
  echo
  echo "Options:"
  echo "  -i    Target IP address"
  echo "  -P    Ports to scan (default: 1-65535)"
  echo "  -u    Username for authentication"
  echo "  -w    Password for authentication"
  echo "  -d    Domain name"
  exit 1
}

# ====== Parse arguments ======
while getopts "i:P:u:w:d:" opt; do
  case $opt in
    i) IP="$OPTARG" ;;
    P) PORTS="$OPTARG" ;;
    u) USERNAME="$OPTARG" ;;
    w) PASSWORD="$OPTARG" ;;
    d) DOMAIN="$OPTARG" ;;
    *) usage ;;
  esac
done

# ====== Check required ======
if [ -z "$IP" ]; then
  echo "❌ Error: Missing required arguments."
  usage
fi

# Run rustscan and save output to a temporary file
RUSTSCAN_OUTPUT_FILE=$(mktemp)
rustscan -a $IP -r 1-65526 --ulimit 5000 > "$RUSTSCAN_OUTPUT_FILE"

cat $RUSTSCAN_OUTPUT_FILE

echo "Rustscan Completed"

# Arrays to collect results
PORTS=()
SERVICES=()

# Extract open ports and services from the Nmap section of rustscan output
in_nmap_section=false
while read -r line; do
  if [[ $line =~ ^PORT[[:space:]]+STATE[[:space:]]+SERVICE ]]; then
    in_nmap_section=true
    continue
  fi

  if $in_nmap_section; then
    port=$(echo "$line" | awk '/open/ {print $1}' | cut -d'/' -f1)
    service=$(echo "$line" | awk '/open/ {print $3}')
    if [[ -n "$port" && -n "$service" ]]; then
      PORTS+=("$port")
      SERVICES+=("$service")
    elif [[ $line =~ ^[A-Za-z] ]]; then
      break
    fi
  fi
done < "$RUSTSCAN_OUTPUT_FILE"

# Join ports for -p
PORT_ARG=$(IFS=, ; echo "${PORTS[*]}")

# Deduplicate and generate script string
SCRIPT_PATTERNS=()
for service in "${SERVICES[@]}"; do
  service_lower=$(echo "$service" | tr '[:upper:]' '[:lower:]')

  case "$service_lower" in
    *smb*|netbios*|microsoft-ds) SCRIPT_PATTERNS+=("smb*") ;;
    *ftp*) SCRIPT_PATTERNS+=("ftp*") ;;
    *http*) SCRIPT_PATTERNS+=("http*") ;;
    *ssh*) SCRIPT_PATTERNS+=("ssh*") ;;
    *mysql*) SCRIPT_PATTERNS+=("mysql*") ;;
    *dns*|*domain*) SCRIPT_PATTERNS+=("dns*") ;;
    *redis*) SCRIPT_PATTERNS+=("redis*") ;;
    *mongodb*) SCRIPT_PATTERNS+=("mongodb*") ;;
    *postgres*) SCRIPT_PATTERNS+=("postgres*") ;;
    *oracle*) SCRIPT_PATTERNS+=("oracle*") ;;
    *ms-sql*) SCRIPT_PATTERNS+=("ms-sql*") ;;
    *ldap*) SCRIPT_PATTERNS+=("ldap*") ;;
    *imap*) SCRIPT_PATTERNS+=("imap*") ;;
    *pop3*) SCRIPT_PATTERNS+=("pop3*") ;;
    *smtp*) SCRIPT_PATTERNS+=("smtp*") ;;
    *rdp*) SCRIPT_PATTERNS+=("rdp*") ;;
    *vnc*) SCRIPT_PATTERNS+=("vnc*") ;;
    *telnet*) SCRIPT_PATTERNS+=("telnet*") ;;
    *nfs*) SCRIPT_PATTERNS+=("nfs*") ;;
    *msrpc*) SCRIPT_PATTERNS+=("msrpc*") ;;
    ms-wbt*) SCRIPT_PATTERNS+=("rdp*") ;;
  esac
  
done

# Remove duplicates and join with commas for Nmap --script
SCRIPT_ARG=$(printf "%s\n" "${SCRIPT_PATTERNS[@]}" | sort -u | paste -sd "," -)

# Show what will be run
echo "[*] Open ports: $PORT_ARG"
echo "[*] Scripts to run: $SCRIPT_ARG"

# ====== Prepare variables ======
CLEAN_IP="${IP//./_}"
OUTPUT_DIR=$(pwd)
OUTPUT_NAME="${CLEAN_IP}_nmap_vuln_scan.xml"

# ====== Start scan ======
echo "🚀 Starting Nmap scan on $IP ..."
nmap -p$PORT_ARG -sV -Pn -A --script="$SCRIPT_ARG" --script-timeout 7m \
  --script-args "smbdomain=$DOMAIN,smbusername=$USERNAME,smbpassword=$PASSWORD" \
  -oX "${OUTPUT_DIR}/$OUTPUT_NAME" $IP

# ====== Convert report to HTML ======
if [ -f "$OUTPUT_DIR/$OUTPUT_NAME" ]; then
  echo "🧩 Generating HTML report ..."
  xsltproc -o "${OUTPUT_DIR}/${OUTPUT_NAME}.html" /home/kali/Desktop/NetworkTools/nmap-bootstrap.xsl "${OUTPUT_DIR}/${OUTPUT_NAME}" &&  rm -rf "${OUTPUT_DIR}/${OUTPUT_NAME}"

  echo "✅ Report saved to ${OUTPUT_NAME}.html"

else
  echo "⚠️ XML report not found, skipping HTML conversion."
fi

# Clean up temporary rustscan output file
rm -f "$RUSTSCAN_OUTPUT_FILE"

echo "🎉 Scan completed!"
