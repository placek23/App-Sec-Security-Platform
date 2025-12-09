#!/bin/bash
# Phase 5: Authentication & Authorization Testing - Setup Script

set -e

echo "========================================"
echo "Phase 5: Authentication & Authorization Testing Setup"
echo "========================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

success() {
    echo -e "${GREEN}[+]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

error() {
    echo -e "${RED}[-]${NC} $1"
}

info() {
    echo -e "[*] $1"
}

# Check if running as root for system packages
check_root() {
    if [ "$EUID" -ne 0 ]; then
        warning "Not running as root. Some installations may require sudo."
    fi
}

# Install Python dependencies
install_python_deps() {
    info "Installing Python dependencies..."

    pip install --quiet requests urllib3 pyjwt 2>/dev/null || pip3 install --quiet requests urllib3 pyjwt 2>/dev/null

    if python3 -c "import requests; import jwt" 2>/dev/null; then
        success "Python dependencies installed"
    else
        error "Failed to install Python dependencies"
        exit 1
    fi
}

# Install Hydra
install_hydra() {
    info "Installing THC Hydra..."

    if command -v hydra &> /dev/null; then
        success "Hydra already installed: $(hydra -h 2>&1 | head -1)"
        return
    fi

    # Try apt (Debian/Ubuntu)
    if command -v apt-get &> /dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y -qq hydra hydra-gtk 2>/dev/null || sudo apt-get install -y -qq hydra 2>/dev/null
        if command -v hydra &> /dev/null; then
            success "Hydra installed via apt"
            return
        fi
    fi

    # Try yum (RHEL/CentOS)
    if command -v yum &> /dev/null; then
        sudo yum install -y hydra 2>/dev/null
        if command -v hydra &> /dev/null; then
            success "Hydra installed via yum"
            return
        fi
    fi

    # Try brew (macOS)
    if command -v brew &> /dev/null; then
        brew install hydra 2>/dev/null
        if command -v hydra &> /dev/null; then
            success "Hydra installed via brew"
            return
        fi
    fi

    # Build from source
    warning "Installing Hydra from source..."
    cd ~/tools 2>/dev/null || mkdir -p ~/tools && cd ~/tools

    if [ ! -d "thc-hydra" ]; then
        git clone --depth 1 https://github.com/vanhauser-thc/thc-hydra.git
    fi

    cd thc-hydra
    ./configure --quiet
    make --quiet
    sudo make install --quiet

    if command -v hydra &> /dev/null; then
        success "Hydra installed from source"
    else
        error "Failed to install Hydra"
    fi
}

# Install jwt_tool (external tool)
install_jwt_tool() {
    info "Installing jwt_tool..."

    if command -v jwt_tool &> /dev/null || [ -f ~/tools/jwt_tool/jwt_tool.py ]; then
        success "jwt_tool already installed"
        return
    fi

    mkdir -p ~/tools
    cd ~/tools

    if [ ! -d "jwt_tool" ]; then
        git clone --depth 1 https://github.com/ticarpi/jwt_tool.git
    fi

    cd jwt_tool
    pip install -r requirements.txt --quiet 2>/dev/null || pip3 install -r requirements.txt --quiet 2>/dev/null
    chmod +x jwt_tool.py

    # Create symlink
    sudo ln -sf ~/tools/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool 2>/dev/null || \
        ln -sf ~/tools/jwt_tool/jwt_tool.py ~/.local/bin/jwt_tool 2>/dev/null

    success "jwt_tool installed"
}

# Download wordlists
download_wordlists() {
    info "Downloading additional wordlists..."

    WORDLIST_DIR="$(dirname "$0")/../config/wordlists"
    mkdir -p "$WORDLIST_DIR"
    cd "$WORDLIST_DIR"

    # SecLists passwords (top 10k)
    if [ ! -f "10k-most-common-full.txt" ]; then
        curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt" \
            -o "10k-most-common-full.txt" 2>/dev/null && \
            success "Downloaded 10k-most-common passwords" || \
            warning "Could not download 10k passwords list"
    fi

    # Top usernames
    if [ ! -f "top-usernames-full.txt" ]; then
        curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt" \
            -o "top-usernames-full.txt" 2>/dev/null && \
            success "Downloaded top usernames" || \
            warning "Could not download usernames list"
    fi

    # Default credentials
    if [ ! -f "default-creds.txt" ]; then
        curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/default-passwords.csv" \
            -o "default-creds.txt" 2>/dev/null && \
            success "Downloaded default credentials" || \
            warning "Could not download default credentials"
    fi
}

# Create payload directories
setup_payloads() {
    info "Setting up payload directories..."

    PAYLOAD_DIR="$(dirname "$0")/../config/payloads/auth"
    mkdir -p "$PAYLOAD_DIR"/{bypass,jwt,credentials,idor}

    success "Payload directories created"
}

# Verify installations
verify_installation() {
    echo ""
    echo "========================================"
    echo "Verifying Installation"
    echo "========================================"

    # Python modules
    info "Checking Python modules..."
    python3 -c "import requests" 2>/dev/null && success "requests: OK" || error "requests: MISSING"
    python3 -c "import jwt" 2>/dev/null && success "pyjwt: OK" || error "pyjwt: MISSING"
    python3 -c "import urllib3" 2>/dev/null && success "urllib3: OK" || error "urllib3: MISSING"

    # External tools
    info "Checking external tools..."
    command -v hydra &> /dev/null && success "hydra: OK" || warning "hydra: NOT FOUND (optional)"

    # Wrappers
    info "Checking wrapper imports..."
    cd "$(dirname "$0")/.."
    python3 -c "from wrappers.auth import AuthBypassTester" 2>/dev/null && \
        success "AuthBypassTester: OK" || error "AuthBypassTester: IMPORT FAILED"
    python3 -c "from wrappers.auth import IDORTester" 2>/dev/null && \
        success "IDORTester: OK" || error "IDORTester: IMPORT FAILED"
    python3 -c "from wrappers.auth import JWTAttacksTester" 2>/dev/null && \
        success "JWTAttacksTester: OK" || error "JWTAttacksTester: IMPORT FAILED"
    python3 -c "from wrappers.auth import PrivilegeEscalationTester" 2>/dev/null && \
        success "PrivilegeEscalationTester: OK" || error "PrivilegeEscalationTester: IMPORT FAILED"
    python3 -c "from wrappers.auth import HydraWrapper" 2>/dev/null && \
        success "HydraWrapper: OK" || error "HydraWrapper: IMPORT FAILED"

    # Workflow
    python3 -c "from workflows.auth_testing import AuthTestingWorkflow" 2>/dev/null && \
        success "AuthTestingWorkflow: OK" || error "AuthTestingWorkflow: IMPORT FAILED"
}

# Main installation
main() {
    check_root

    echo "Installing Phase 5 components..."
    echo ""

    install_python_deps
    install_hydra
    install_jwt_tool
    download_wordlists
    setup_payloads
    verify_installation

    echo ""
    echo "========================================"
    echo "Phase 5 Setup Complete!"
    echo "========================================"
    echo ""
    echo "Usage examples:"
    echo "  # Auth bypass testing"
    echo "  python wrappers/auth/auth_bypass.py -u https://example.com/login"
    echo ""
    echo "  # IDOR testing"
    echo "  python wrappers/auth/idor_tester.py -u 'https://api.example.com/users/{id}' -p id"
    echo ""
    echo "  # JWT attacks"
    echo "  python wrappers/auth/jwt_attacks.py -t 'eyJhbG...' --url https://api.example.com/me"
    echo ""
    echo "  # Full workflow"
    echo "  python workflows/auth_testing.py -t https://example.com --login-url /login"
    echo ""
}

main "$@"
