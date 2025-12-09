#!/bin/bash
# Phase 3: Advanced Injection Testing Setup Script
# This script installs the required tools and dependencies for Phase 3

set -e

echo "======================================"
echo "Phase 3: Advanced Injection Testing"
echo "======================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to print status
print_status() {
    if [ "$2" == "ok" ]; then
        echo -e "${GREEN}[+]${NC} $1"
    elif [ "$2" == "warn" ]; then
        echo -e "${YELLOW}[!]${NC} $1"
    else
        echo -e "${RED}[-]${NC} $1"
    fi
}

# Check prerequisites
echo "[*] Checking prerequisites..."

if ! command_exists python3; then
    print_status "Python3 not found. Please install Python 3.8+" "error"
    exit 1
fi

if ! command_exists pip3 && ! command_exists pip; then
    print_status "pip not found. Please install pip" "error"
    exit 1
fi

PIP_CMD="pip3"
if ! command_exists pip3; then
    PIP_CMD="pip"
fi

print_status "Python3 found: $(python3 --version)" "ok"

# Check for Go (optional but recommended)
if ! command_exists go; then
    print_status "Go not found. Some tools require Go to be installed" "warn"
    GO_AVAILABLE=false
else
    print_status "Go found: $(go version)" "ok"
    GO_AVAILABLE=true
fi

echo ""
echo "[*] Installing Python dependencies..."

# Core dependencies for Phase 3 wrappers
$PIP_CMD install --quiet requests 2>/dev/null && print_status "requests installed" "ok" || print_status "Failed to install requests" "error"
$PIP_CMD install --quiet urllib3 2>/dev/null && print_status "urllib3 installed" "ok" || print_status "Failed to install urllib3" "error"

# SQLMap (upgrade to latest)
echo ""
echo "[*] Installing/Upgrading SQLMap..."
$PIP_CMD install --upgrade --quiet sqlmap 2>/dev/null && print_status "sqlmap installed/upgraded" "ok" || print_status "Failed to install sqlmap" "warn"

# LDAP tools
echo ""
echo "[*] Installing LDAP testing dependencies..."
$PIP_CMD install --quiet ldap3 2>/dev/null && print_status "ldap3 installed" "ok" || print_status "Failed to install ldap3" "warn"

# XML/XPath tools
echo ""
echo "[*] Installing XML/XPath testing dependencies..."
$PIP_CMD install --quiet lxml 2>/dev/null && print_status "lxml installed" "ok" || print_status "Failed to install lxml" "warn"

# Commix (command injection)
echo ""
echo "[*] Installing Commix..."
$PIP_CMD install --quiet commix 2>/dev/null && print_status "commix installed" "ok" || print_status "Failed to install commix" "warn"

echo ""
echo "[*] Setting up payload repositories..."

# Create tools directory if it doesn't exist
TOOLS_DIR="$HOME/tools"
mkdir -p "$TOOLS_DIR"

# Clone PayloadsAllTheThings if not exists
if [ ! -d "$TOOLS_DIR/PayloadsAllTheThings" ]; then
    echo "[*] Cloning PayloadsAllTheThings..."
    git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git "$TOOLS_DIR/PayloadsAllTheThings" 2>/dev/null && \
        print_status "PayloadsAllTheThings cloned" "ok" || \
        print_status "Failed to clone PayloadsAllTheThings" "warn"
else
    print_status "PayloadsAllTheThings already exists" "ok"
fi

# Clone NoSQLMap if not exists
if [ ! -d "$TOOLS_DIR/NoSQLMap" ]; then
    echo "[*] Cloning NoSQLMap..."
    git clone https://github.com/codingo/NoSQLMap.git "$TOOLS_DIR/NoSQLMap" 2>/dev/null && \
        print_status "NoSQLMap cloned" "ok" || \
        print_status "Failed to clone NoSQLMap" "warn"

    # Install NoSQLMap requirements
    if [ -f "$TOOLS_DIR/NoSQLMap/requirements.txt" ]; then
        $PIP_CMD install --quiet -r "$TOOLS_DIR/NoSQLMap/requirements.txt" 2>/dev/null || true
    fi
else
    print_status "NoSQLMap already exists" "ok"
fi

echo ""
echo "[*] Creating output directories..."
mkdir -p ./output/injection/sql
mkdir -p ./output/injection/nosql
mkdir -p ./output/injection/ldap
mkdir -p ./output/injection/xpath
mkdir -p ./output/injection/xss
print_status "Output directories created" "ok"

echo ""
echo "[*] Verifying payload files..."
PAYLOAD_DIR="./config/payloads/injection"
if [ -d "$PAYLOAD_DIR" ]; then
    echo "    Found payload directories:"
    ls -la "$PAYLOAD_DIR" 2>/dev/null | grep "^d" | awk '{print "      - " $NF}' | grep -v "^\.\.$" | grep -v "^\.$"
    print_status "Payload files verified" "ok"
else
    print_status "Payload directory not found" "warn"
fi

echo ""
echo "======================================"
echo "Phase 3 Setup Summary"
echo "======================================"
echo ""

# Final validation
echo "[*] Validating Python imports..."
python3 -c "import requests; print('[+] requests: OK')" 2>/dev/null || echo "[-] requests: Not available"
python3 -c "import ldap3; print('[+] ldap3: OK')" 2>/dev/null || echo "[-] ldap3: Not available"
python3 -c "from lxml import etree; print('[+] lxml: OK')" 2>/dev/null || echo "[-] lxml: Not available"

echo ""
echo "[*] Validating command-line tools..."
if command_exists sqlmap; then
    print_status "sqlmap: $(sqlmap --version 2>&1 | head -n1)" "ok"
else
    print_status "sqlmap: Not found in PATH" "warn"
fi

if command_exists commix; then
    print_status "commix: Available" "ok"
else
    print_status "commix: Not found in PATH" "warn"
fi

echo ""
echo "[*] Validating Phase 3 wrappers..."
python3 -c "from wrappers.injection import NoSQLInjectionTester; print('[+] NoSQLInjectionTester: OK')" 2>/dev/null || echo "[-] NoSQLInjectionTester: Import failed"
python3 -c "from wrappers.injection import LDAPInjectionTester; print('[+] LDAPInjectionTester: OK')" 2>/dev/null || echo "[-] LDAPInjectionTester: Import failed"
python3 -c "from wrappers.injection import XPathInjectionTester; print('[+] XPathInjectionTester: OK')" 2>/dev/null || echo "[-] XPathInjectionTester: Import failed"
python3 -c "from wrappers.injection import AdvancedXSSTester; print('[+] AdvancedXSSTester: OK')" 2>/dev/null || echo "[-] AdvancedXSSTester: Import failed"

echo ""
echo "======================================"
echo "Usage Examples"
echo "======================================"
echo ""
echo "[*] NoSQL Injection Testing:"
echo "    python3 wrappers/injection/nosql_injection.py -u 'https://example.com/api' -p username"
echo "    python3 wrappers/injection/nosql_injection.py -u 'https://example.com/login' --test-auth"
echo ""
echo "[*] LDAP Injection Testing:"
echo "    python3 wrappers/injection/ldap_injection.py -u 'https://example.com/search' -p query"
echo "    python3 wrappers/injection/ldap_injection.py -u 'https://example.com/auth' -p user --test-blind"
echo ""
echo "[*] XPath Injection Testing:"
echo "    python3 wrappers/injection/xpath_injection.py -u 'https://example.com/xml' -p id"
echo "    python3 wrappers/injection/xpath_injection.py -u 'https://example.com/search' -p q --test-blind"
echo ""
echo "[*] Advanced XSS Testing:"
echo "    python3 wrappers/injection/advanced_xss.py -u 'https://example.com/search' -p q"
echo "    python3 wrappers/injection/advanced_xss.py -u 'https://example.com/page' -p input --test-dom"
echo ""

print_status "Phase 3 setup complete!" "ok"
