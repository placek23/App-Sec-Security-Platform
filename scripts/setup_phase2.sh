#!/bin/bash
# Phase 2: Manual Testing Support & Proxy Integration Setup Script
# This script installs the required tools for Phase 2

set -e

echo "======================================"
echo "Phase 2: Proxy & Manual Testing Setup"
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

# Install Python packages for Phase 2
$PIP_CMD install --quiet python-owasp-zap-v2.4 2>/dev/null && print_status "python-owasp-zap-v2.4 installed" "ok" || print_status "Failed to install python-owasp-zap-v2.4" "error"
$PIP_CMD install --quiet mitmproxy 2>/dev/null && print_status "mitmproxy installed" "ok" || print_status "Failed to install mitmproxy" "warn"
$PIP_CMD install --quiet pycryptodome 2>/dev/null && print_status "pycryptodome installed" "ok" || print_status "Failed to install pycryptodome" "error"
$PIP_CMD install --quiet base58 2>/dev/null && print_status "base58 installed" "ok" || print_status "Failed to install base58" "error"
$PIP_CMD install --quiet python-jose 2>/dev/null && print_status "python-jose installed" "ok" || print_status "Failed to install python-jose" "error"
$PIP_CMD install --quiet pyjwt 2>/dev/null && print_status "pyjwt installed" "ok" || print_status "Failed to install pyjwt" "error"

echo ""
echo "[*] Installing Go tools (if Go is available)..."

if [ "$GO_AVAILABLE" = true ]; then
    # ffuf - Fast web fuzzer
    if ! command_exists ffuf; then
        echo "[*] Installing ffuf..."
        go install github.com/ffuf/ffuf/v2@latest 2>/dev/null && print_status "ffuf installed" "ok" || print_status "Failed to install ffuf" "warn"
    else
        print_status "ffuf already installed" "ok"
    fi
else
    print_status "Skipping Go tools (Go not installed)" "warn"
fi

echo ""
echo "[*] ZAP Installation Instructions..."
echo ""
print_status "OWASP ZAP must be installed separately:" "warn"
echo "    Option 1 (Snap): sudo snap install zaproxy --classic"
echo "    Option 2 (Download): https://www.zaproxy.org/download/"
echo "    Option 3 (Docker): docker pull ghcr.io/zaproxy/zaproxy:stable"
echo ""

# Check if ZAP is installed
if command_exists zap.sh; then
    print_status "ZAP found at $(which zap.sh)" "ok"
elif command_exists zaproxy; then
    print_status "ZAP found at $(which zaproxy)" "ok"
else
    print_status "ZAP not found in PATH (may need manual installation)" "warn"
fi

# Check mitmproxy
echo ""
if command_exists mitmproxy; then
    print_status "mitmproxy found: $(mitmproxy --version 2>&1 | head -n1)" "ok"
else
    print_status "mitmproxy not found in PATH" "warn"
fi

echo ""
echo "[*] Creating output directories..."
mkdir -p ./output/zap
mkdir -p ./output/sessions
mkdir -p ./output/proxy
print_status "Output directories created" "ok"

echo ""
echo "======================================"
echo "Phase 2 Setup Summary"
echo "======================================"
echo ""

# Final validation
echo "[*] Validating installation..."
python3 -c "from zapv2 import ZAPv2; print('[+] ZAP API: OK')" 2>/dev/null || echo "[-] ZAP API: Not available"
python3 -c "import jwt; print('[+] PyJWT: OK')" 2>/dev/null || echo "[-] PyJWT: Not available"
python3 -c "from jose import jwt; print('[+] python-jose: OK')" 2>/dev/null || echo "[-] python-jose: Not available"
python3 -c "from Crypto.Cipher import AES; print('[+] pycryptodome: OK')" 2>/dev/null || echo "[-] pycryptodome: Not available"
python3 -c "import base58; print('[+] base58: OK')" 2>/dev/null || echo "[-] base58: Not available"

echo ""
echo "[*] To test the ZAP integration:"
echo "    1. Start ZAP with API enabled"
echo "    2. Run: python3 wrappers/proxy/zap_integration.py --target https://example.com --full"
echo ""
echo "[*] To test the request builder:"
echo "    Run: python3 wrappers/proxy/request_builder.py --url https://httpbin.org/get"
echo ""
echo "[*] To test the encoder:"
echo "    Run: python3 utils/encoder.py \"<script>alert(1)</script>\""
echo ""

print_status "Phase 2 setup complete!" "ok"
