#!/bin/bash
#
# Phase 4: API & Modern Application Testing - Setup Script
#
# This script installs all required tools and dependencies for Phase 4.
#

set -e

echo "=============================================="
echo "Phase 4: API & Modern Application Testing"
echo "=============================================="
echo ""

# Get the script's directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Activate virtual environment if it exists
VENV_DIR="${PROJECT_ROOT}/venv"
if [ -d "${VENV_DIR}" ]; then
    echo "Activating virtual environment..."
    source "${VENV_DIR}/bin/activate"
else
    echo "Creating virtual environment..."
    python3 -m venv "${VENV_DIR}"
    source "${VENV_DIR}/bin/activate"
fi

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print status
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    print_warning "Running as root. Some Go tools should be installed as regular user."
fi

# Create tools directory
TOOLS_DIR="${HOME}/tools"
mkdir -p "${TOOLS_DIR}"

echo ""
echo "=============================================="
echo "Installing Python Dependencies"
echo "=============================================="
echo ""

# Core Python dependencies
print_status "Installing core Python dependencies..."
pip install --upgrade pip
pip install requests pyyaml aiohttp

# GraphQL dependencies
print_status "Installing GraphQL dependencies..."
pip install graphql-core gql

# WebSocket dependencies
print_status "Installing WebSocket dependencies..."
pip install websocket-client websockets

# JWT dependencies
print_status "Installing JWT dependencies..."
pip install pyjwt python-jose

# OpenAPI/Swagger dependencies
print_status "Installing OpenAPI/Swagger dependencies..."
pip install openapi-spec-validator prance

# Newman (Postman CLI)
print_status "Checking for npm..."
if command -v npm &> /dev/null; then
    print_status "Installing Newman (Postman CLI)..."
    npm install -g newman || print_warning "Newman installation failed (may need sudo)"
else
    print_warning "npm not found. Skipping Newman installation."
    print_warning "Install Node.js and npm, then run: npm install -g newman"
fi

echo ""
echo "=============================================="
echo "Installing Go Tools"
echo "=============================================="
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    print_warning "Go is not installed. Please install Go 1.19+ first."
    print_warning "Visit: https://golang.org/dl/"
else
    # Kiterunner - API endpoint discovery
    print_status "Installing Kiterunner..."
    go install github.com/assetnote/kiterunner/cmd/kr@latest || print_warning "Kiterunner installation failed"

    # jwt_tool (Go version)
    print_status "Note: jwt_tool is Python-based, installing separately..."
fi

echo ""
echo "=============================================="
echo "Installing Additional Tools"
echo "=============================================="
echo ""

# jwt_tool (Python)
print_status "Installing jwt_tool..."
cd "${TOOLS_DIR}"
if [ ! -d "jwt_tool" ]; then
    git clone https://github.com/ticarpi/jwt_tool.git
    cd jwt_tool
    pip install -r requirements.txt || print_warning "jwt_tool dependencies failed"
else
    print_status "jwt_tool already exists, updating..."
    cd jwt_tool
    git pull
fi
cd "${TOOLS_DIR}"

# Download Kitebuilder routes (for Kiterunner)
print_status "Downloading Kitebuilder routes..."
KITE_DIR="${HOME}/.kiterunner"
mkdir -p "${KITE_DIR}"
cd "${KITE_DIR}"

if [ ! -f "routes-large.kite" ]; then
    print_status "Downloading routes-large.kite..."
    # Note: You may need to download this from Assetnote's repository
    curl -L -o routes-large.kite "https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite" || \
        print_warning "Could not download Kitebuilder routes. Download manually from Assetnote."
else
    print_status "Kitebuilder routes already exist."
fi

echo ""
echo "=============================================="
echo "Creating Payload Directories"
echo "=============================================="
echo ""

# Create payload directories
PAYLOAD_DIR="$(dirname "$0")/../config/payloads/api"
mkdir -p "${PAYLOAD_DIR}/graphql"
mkdir -p "${PAYLOAD_DIR}/jwt"
mkdir -p "${PAYLOAD_DIR}/websocket"
mkdir -p "${PAYLOAD_DIR}/openapi"

print_status "Created payload directories in config/payloads/api/"

echo ""
echo "=============================================="
echo "Installation Summary"
echo "=============================================="
echo ""

# Check installations
echo "Checking installations..."
echo ""

# Python packages
print_status "Python packages:"
python3 -c "import requests; print('  - requests: OK')" 2>/dev/null || print_error "  - requests: MISSING"
python3 -c "import yaml; print('  - pyyaml: OK')" 2>/dev/null || print_error "  - pyyaml: MISSING"
python3 -c "import aiohttp; print('  - aiohttp: OK')" 2>/dev/null || print_error "  - aiohttp: MISSING"
python3 -c "import gql; print('  - gql: OK')" 2>/dev/null || print_error "  - gql: MISSING"
python3 -c "import websocket; print('  - websocket-client: OK')" 2>/dev/null || print_error "  - websocket-client: MISSING"
python3 -c "import jwt; print('  - pyjwt: OK')" 2>/dev/null || print_error "  - pyjwt: MISSING"
python3 -c "import jose; print('  - python-jose: OK')" 2>/dev/null || print_error "  - python-jose: MISSING"

echo ""
print_status "Go tools:"
command -v kr &> /dev/null && print_status "  - kr (Kiterunner): OK" || print_warning "  - kr (Kiterunner): NOT IN PATH"

echo ""
print_status "External tools:"
command -v newman &> /dev/null && print_status "  - newman: OK" || print_warning "  - newman: NOT INSTALLED"
[ -f "${TOOLS_DIR}/jwt_tool/jwt_tool.py" ] && print_status "  - jwt_tool: OK" || print_warning "  - jwt_tool: NOT INSTALLED"

echo ""
echo "=============================================="
echo "Next Steps"
echo "=============================================="
echo ""
echo "1. Run the validation script to verify installation:"
echo "   python scripts/validate_phase4.py"
echo ""
echo "2. Test the API workflow:"
echo "   python workflows/api_testing.py -t https://example.com"
echo ""
echo "3. Individual tool usage:"
echo "   python wrappers/api/kiterunner.py -u https://api.example.com"
echo "   python wrappers/api/graphql_tester.py -u https://example.com/graphql"
echo "   python wrappers/api/websocket_tester.py -u wss://example.com/ws"
echo "   python wrappers/api/openapi_analyzer.py -u https://api.example.com"
echo "   python wrappers/api/jwt_tester.py -t 'eyJhbGciOiJIUzI1NiIs...'"
echo ""

print_status "Phase 4 setup complete!"
