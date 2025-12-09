#!/bin/bash
# Phase 3.5: Advanced Web Vulnerabilities - Setup Script
# Installs all required tools for advanced vulnerability testing

set -e

echo "=========================================="
echo "Phase 3.5: Advanced Web Vulnerabilities"
echo "Setup Script"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root for some installations
check_sudo() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}[!] Some installations may require sudo${NC}"
    fi
}

# Check Go installation
check_go() {
    if ! command -v go &> /dev/null; then
        echo -e "${RED}[!] Go is not installed. Please install Go 1.19+${NC}"
        echo "    Visit: https://golang.org/doc/install"
        exit 1
    fi
    echo -e "${GREEN}[+] Go found: $(go version)${NC}"
}

# Check Python installation
check_python() {
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}[!] Python 3 is not installed${NC}"
        exit 1
    fi
    echo -e "${GREEN}[+] Python found: $(python3 --version)${NC}"
}

# Install Python dependencies
install_python_deps() {
    echo -e "\n${YELLOW}[*] Installing Python dependencies...${NC}"

    pip3 install --user aiohttp asyncio
    pip3 install --user h2
    pip3 install --user python-magic 2>/dev/null || echo "python-magic optional"

    echo -e "${GREEN}[+] Python dependencies installed${NC}"
}

# Install Go tools
install_go_tools() {
    echo -e "\n${YELLOW}[*] Installing Go tools...${NC}"

    # Interactsh client for OOB callbacks
    echo "[*] Installing interactsh-client..."
    go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

    echo -e "${GREEN}[+] Go tools installed${NC}"
}

# Clone external tools
install_external_tools() {
    echo -e "\n${YELLOW}[*] Installing external tools...${NC}"

    TOOLS_DIR="${HOME}/tools"
    mkdir -p "$TOOLS_DIR"
    cd "$TOOLS_DIR"

    # SSRFmap
    if [ ! -d "SSRFmap" ]; then
        echo "[*] Cloning SSRFmap..."
        git clone https://github.com/swisskyrepo/SSRFmap.git
        cd SSRFmap && pip3 install --user -r requirements.txt 2>/dev/null || true
        cd ..
    else
        echo "[+] SSRFmap already exists"
    fi

    # Gopherus (for SSRF exploitation)
    if [ ! -d "Gopherus" ]; then
        echo "[*] Cloning Gopherus..."
        git clone https://github.com/tarunkant/Gopherus.git
    else
        echo "[+] Gopherus already exists"
    fi

    # XXEinjector
    if [ ! -d "XXEinjector" ]; then
        echo "[*] Cloning XXEinjector..."
        git clone https://github.com/enjoiz/XXEinjector.git
    else
        echo "[+] XXEinjector already exists"
    fi

    # HTTP Request Smuggler
    if [ ! -d "smuggler" ]; then
        echo "[*] Cloning smuggler..."
        git clone https://github.com/defparam/smuggler.git
    else
        echo "[+] smuggler already exists"
    fi

    # Corsy (CORS testing)
    if [ ! -d "Corsy" ]; then
        echo "[*] Cloning Corsy..."
        git clone https://github.com/s0md3v/Corsy.git
        cd Corsy && pip3 install --user -r requirements.txt 2>/dev/null || true
        cd ..
    else
        echo "[+] Corsy already exists"
    fi

    # OpenRedireX
    if [ ! -d "OpenRedireX" ]; then
        echo "[*] Cloning OpenRedireX..."
        git clone https://github.com/devanshbatham/OpenRedireX.git
    else
        echo "[+] OpenRedireX already exists"
    fi

    echo -e "${GREEN}[+] External tools installed${NC}"
}

# Create payload directories
setup_payloads() {
    echo -e "\n${YELLOW}[*] Setting up payload directories...${NC}"

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

    mkdir -p "$PROJECT_DIR/config/payloads/advanced/ssrf"
    mkdir -p "$PROJECT_DIR/config/payloads/advanced/xxe"
    mkdir -p "$PROJECT_DIR/config/payloads/advanced/deserialization"
    mkdir -p "$PROJECT_DIR/config/payloads/advanced/smuggling"
    mkdir -p "$PROJECT_DIR/config/payloads/advanced/cors"
    mkdir -p "$PROJECT_DIR/config/payloads/advanced/upload"

    echo -e "${GREEN}[+] Payload directories created${NC}"
}

# Verify installations
verify_installation() {
    echo -e "\n${YELLOW}[*] Verifying installations...${NC}"

    ERRORS=0

    # Check interactsh-client
    if command -v interactsh-client &> /dev/null; then
        echo -e "${GREEN}[+] interactsh-client: OK${NC}"
    else
        echo -e "${RED}[-] interactsh-client: NOT FOUND${NC}"
        ERRORS=$((ERRORS + 1))
    fi

    # Check Python imports
    echo "[*] Checking Python imports..."

    python3 -c "import aiohttp; print('aiohttp OK')" 2>/dev/null || {
        echo -e "${RED}[-] aiohttp: NOT FOUND${NC}"
        ERRORS=$((ERRORS + 1))
    }

    python3 -c "import h2; print('h2 OK')" 2>/dev/null || {
        echo -e "${YELLOW}[!] h2: NOT FOUND (optional for HTTP/2)${NC}"
    }

    python3 -c "import requests; print('requests OK')" 2>/dev/null || {
        echo -e "${RED}[-] requests: NOT FOUND${NC}"
        ERRORS=$((ERRORS + 1))
    }

    if [ $ERRORS -eq 0 ]; then
        echo -e "\n${GREEN}=========================================="
        echo "All required tools installed successfully!"
        echo "==========================================${NC}"
    else
        echo -e "\n${YELLOW}=========================================="
        echo "Installation completed with $ERRORS warning(s)"
        echo "Some optional tools may not be installed"
        echo "==========================================${NC}"
    fi
}

# Main execution
main() {
    check_sudo
    check_go
    check_python

    install_python_deps
    install_go_tools
    install_external_tools
    setup_payloads
    verify_installation

    echo -e "\n${GREEN}[+] Phase 3.5 setup complete!${NC}"
    echo ""
    echo "Usage examples:"
    echo "  python workflows/advanced_vulns.py -t https://example.com"
    echo "  python wrappers/advanced/ssrf_tester.py -u https://example.com/fetch -p url"
    echo "  python wrappers/advanced/xxe_injector.py -u https://example.com/api/xml"
    echo "  python wrappers/advanced/cors_tester.py -u https://example.com/api"
}

main "$@"
