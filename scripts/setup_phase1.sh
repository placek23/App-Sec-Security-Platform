#!/bin/bash
# Phase 1: Enhanced Web Discovery & Reconnaissance - Setup Script
# Run this script to install all Phase 1 tools

set -e

echo "============================================"
echo "Phase 1: Web Discovery & Reconnaissance Setup"
echo "============================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create tools directory
TOOLS_DIR="$HOME/tools"
mkdir -p "$TOOLS_DIR"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to print status
print_status() {
    if [ "$2" = "ok" ]; then
        echo -e "${GREEN}[✓]${NC} $1"
    elif [ "$2" = "fail" ]; then
        echo -e "${RED}[✗]${NC} $1"
    else
        echo -e "${YELLOW}[*]${NC} $1"
    fi
}

echo "Checking prerequisites..."
echo ""

# Check Go
if command_exists go; then
    GO_VERSION=$(go version | awk '{print $3}')
    print_status "Go installed: $GO_VERSION" "ok"
else
    print_status "Go not found - please install Go 1.19+" "fail"
    echo "  Install from: https://go.dev/dl/"
fi

# Check Python
if command_exists python3; then
    PYTHON_VERSION=$(python3 --version)
    print_status "Python installed: $PYTHON_VERSION" "ok"
else
    print_status "Python3 not found" "fail"
fi

# Check pip
if command_exists pip3; then
    print_status "pip3 installed" "ok"
else
    print_status "pip3 not found" "fail"
fi

# Check git
if command_exists git; then
    print_status "git installed" "ok"
else
    print_status "git not found" "fail"
fi

echo ""
echo "Installing Go tools..."
echo ""

# Install Go tools
GO_TOOLS=(
    "github.com/OJ/gobuster/v3@latest"
    "github.com/sensepost/gowitness@latest"
    "github.com/lc/subjs@latest"
    "github.com/Sh1Yo/x8@latest"
)

for tool in "${GO_TOOLS[@]}"; do
    tool_name=$(echo "$tool" | sed 's|.*/||' | sed 's|@.*||')
    echo -n "Installing $tool_name... "
    if go install "$tool" 2>/dev/null; then
        print_status "$tool_name" "ok"
    else
        print_status "$tool_name - install failed" "fail"
    fi
done

echo ""
echo "Installing Python tools..."
echo ""

# Install Python tools
pip3 install --quiet dirsearch wfuzz 2>/dev/null && print_status "dirsearch & wfuzz" "ok" || print_status "dirsearch & wfuzz" "fail"

echo ""
echo "Installing LinkFinder..."
echo ""

# Install LinkFinder
if [ ! -d "$TOOLS_DIR/LinkFinder" ]; then
    cd "$TOOLS_DIR"
    git clone https://github.com/GerbenJavado/LinkFinder.git 2>/dev/null
    cd LinkFinder
    pip3 install -r requirements.txt --quiet 2>/dev/null
    python3 setup.py install --quiet 2>/dev/null
    print_status "LinkFinder installed" "ok"
else
    print_status "LinkFinder already exists" "ok"
fi

echo ""
echo "Installing SecretFinder..."
echo ""

# Install SecretFinder
if [ ! -d "$TOOLS_DIR/SecretFinder" ]; then
    cd "$TOOLS_DIR"
    git clone https://github.com/m4ll0k/SecretFinder.git 2>/dev/null
    cd SecretFinder
    pip3 install -r requirements.txt --quiet 2>/dev/null
    print_status "SecretFinder installed" "ok"
else
    print_status "SecretFinder already exists" "ok"
fi

echo ""
echo "Installing git-dumper..."
echo ""

# Install git-dumper
if [ ! -d "$TOOLS_DIR/git-dumper" ]; then
    cd "$TOOLS_DIR"
    git clone https://github.com/arthaud/git-dumper.git 2>/dev/null
    cd git-dumper
    pip3 install -r requirements.txt --quiet 2>/dev/null
    print_status "git-dumper installed" "ok"
else
    print_status "git-dumper already exists" "ok"
fi

echo ""
echo "Setting up wordlists..."
echo ""

# Setup wordlists directory
WORDLIST_DIR="$(dirname "$0")/../config/wordlists"
mkdir -p "$WORDLIST_DIR"

# Download common wordlists
cd "$WORDLIST_DIR"

if [ ! -f "common.txt" ]; then
    echo "Downloading common.txt..."
    wget -q https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt -O common.txt 2>/dev/null && \
        print_status "common.txt downloaded" "ok" || print_status "common.txt download failed" "fail"
fi

if [ ! -f "medium.txt" ]; then
    echo "Downloading medium.txt (this may take a moment)..."
    wget -q https://raw.githubusercontent.com/digination/dirbuster-ng/master/wordlists/directory-list-2.3-medium.txt -O medium.txt 2>/dev/null && \
        print_status "medium.txt downloaded" "ok" || print_status "medium.txt download failed" "fail"
fi

# Note about SecLists
echo ""
echo -e "${YELLOW}[*]${NC} For comprehensive wordlists, consider cloning SecLists:"
echo "    cd $WORDLIST_DIR && git clone --depth 1 https://github.com/danielmiessler/SecLists.git"

echo ""
echo "============================================"
echo "Verification"
echo "============================================"
echo ""

# Verify installations
CHECKS=(
    "gobuster:gobuster version"
    "dirsearch:dirsearch --help"
    "gowitness:gowitness --help"
    "LinkFinder:python3 $TOOLS_DIR/LinkFinder/linkfinder.py --help"
    "SecretFinder:python3 $TOOLS_DIR/SecretFinder/SecretFinder.py --help"
)

echo "Checking tool availability..."
echo ""

for check in "${CHECKS[@]}"; do
    tool_name="${check%%:*}"
    tool_cmd="${check#*:}"
    if eval "$tool_cmd" >/dev/null 2>&1; then
        print_status "$tool_name" "ok"
    else
        print_status "$tool_name - not working" "fail"
    fi
done

echo ""
echo "============================================"
echo "Setup Complete!"
echo "============================================"
echo ""
echo "To test Phase 1 tools, run:"
echo "  python3 scripts/test_phase1.py"
echo ""
