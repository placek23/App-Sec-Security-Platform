#!/bin/bash
# Phase 6: Reporting & Integration Enhancement - Setup Script
# This script installs all dependencies required for Phase 6

set -e

echo "=============================================="
echo "Phase 6: Reporting & Integration Enhancement"
echo "Setup Script"
echo "=============================================="
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
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}[OK]${NC} $2"
    else
        echo -e "${RED}[FAILED]${NC} $2"
        return 1
    fi
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_info() {
    echo -e "[INFO] $1"
}

# Check Python version
echo "Checking Python version..."
if command_exists python3; then
    PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
    echo -e "${GREEN}[OK]${NC} Python $PYTHON_VERSION found"
else
    echo -e "${RED}[ERROR]${NC} Python 3 not found. Please install Python 3.8+"
    exit 1
fi

# Check pip
echo "Checking pip..."
if command_exists pip3; then
    echo -e "${GREEN}[OK]${NC} pip3 found"
    PIP="pip3"
elif command_exists pip; then
    echo -e "${GREEN}[OK]${NC} pip found"
    PIP="pip"
else
    echo -e "${RED}[ERROR]${NC} pip not found. Please install pip"
    exit 1
fi

echo ""
echo "Installing Phase 6 Python dependencies..."
echo "=============================================="

# Core reporting dependencies
echo ""
echo "1. Installing ReportLab (PDF generation)..."
$PIP install reportlab --quiet
print_status $? "ReportLab"

echo "2. Installing WeasyPrint (HTML to PDF)..."
# WeasyPrint has system dependencies
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if command_exists apt-get; then
        print_info "Installing system dependencies for WeasyPrint..."
        sudo apt-get update -qq
        sudo apt-get install -y -qq libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info 2>/dev/null || true
    fi
fi
$PIP install weasyprint --quiet 2>/dev/null || print_warning "WeasyPrint installation may have issues - optional dependency"
echo -e "${GREEN}[OK]${NC} WeasyPrint (optional)"

echo "3. Installing SQLAlchemy (Database ORM)..."
$PIP install sqlalchemy --quiet
print_status $? "SQLAlchemy"

echo "4. Installing Alembic (Database migrations)..."
$PIP install alembic --quiet
print_status $? "Alembic"

echo "5. Installing Jinja2 (Templating)..."
$PIP install jinja2 --quiet
print_status $? "Jinja2"

echo "6. Installing Markdown..."
$PIP install markdown --quiet
print_status $? "Markdown"

# Optional API framework
echo ""
echo "Installing optional API framework..."
echo "=============================================="

echo "7. Installing FastAPI (REST API framework)..."
$PIP install fastapi --quiet
print_status $? "FastAPI"

echo "8. Installing Uvicorn (ASGI server)..."
$PIP install uvicorn --quiet
print_status $? "Uvicorn"

# Ensure base dependencies are present
echo ""
echo "Verifying base dependencies..."
echo "=============================================="

echo "9. Installing/updating requests..."
$PIP install requests --quiet
print_status $? "Requests"

echo "10. Installing/updating aiohttp..."
$PIP install aiohttp --quiet
print_status $? "aiohttp"

# Create necessary directories
echo ""
echo "Creating directory structure..."
echo "=============================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

mkdir -p "$PROJECT_DIR/output/reports"
mkdir -p "$PROJECT_DIR/templates/reports"
mkdir -p "$PROJECT_DIR/database"

print_status 0 "Created output/reports directory"
print_status 0 "Created templates/reports directory"
print_status 0 "Created database directory"

# Initialize database
echo ""
echo "Initializing database..."
echo "=============================================="

python3 -c "
import sys
sys.path.insert(0, '$PROJECT_DIR')
try:
    from database.models import init_db
    engine = init_db('sqlite:///$PROJECT_DIR/output/appsec_bounty.db')
    print('Database initialized successfully')
except Exception as e:
    print(f'Database initialization: {e}')
" 2>/dev/null || print_warning "Database will be initialized on first use"

echo ""
echo "=============================================="
echo "Phase 6 Setup Complete!"
echo "=============================================="
echo ""
echo "Installed components:"
echo "  - ReportLab (PDF generation)"
echo "  - WeasyPrint (HTML to PDF - optional)"
echo "  - SQLAlchemy (Database ORM)"
echo "  - Alembic (Database migrations)"
echo "  - Jinja2 (Report templates)"
echo "  - FastAPI + Uvicorn (API framework)"
echo ""
echo "Next steps:"
echo "  1. Run validation: python scripts/validate_phase6.py"
echo "  2. Test reporting: python utils/advanced_reporter.py"
echo "  3. Test database: python database/manager.py"
echo ""
echo "For usage examples, see IMPLEMENTATION_GUIDE.md"
