#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}[*] Starting Nelux 1nject0r installation...${NC}"

# Check for python3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] python3 is not installed. Please install it and try again.${NC}"
    exit 1
fi

# Check for pip
if ! command -v pip &> /dev/null && ! command -v pip3 &> /dev/null; then
    echo -e "${RED}[!] pip is not installed. Please install it and try again.${NC}"
    exit 1
fi

# Set pip command
PIP_CMD="pip"
if command -v pip3 &> /dev/null; then
    PIP_CMD="pip3"
fi

echo -e "${CYAN}[*] Installing Python requirements...${NC}"
$PIP_CMD install -r requirements.txt --break-system-packages 2>/dev/null || $PIP_CMD install -r requirements.txt

echo -e "${CYAN}[*] Installing PyInstaller...${NC}"
$PIP_CMD install pyinstaller --break-system-packages 2>/dev/null || $PIP_CMD install pyinstaller

echo -e "${CYAN}[*] Compiling nelux_injector.py into a standalone binary...${NC}"
python3 -m PyInstaller --onefile nelux_injector.py -n nelux1nject0r

if [ -f "dist/nelux1nject0r" ]; then
    echo -e "${CYAN}[*] Moving binary to /usr/local/bin for global access...${NC}"
    if [ "$EUID" -ne 0 ]; then
        echo -e "${CYAN}[*] Superuser permissions required (sudo) to move binary to /usr/local/bin.${NC}"
        sudo mv dist/nelux1nject0r /usr/local/bin/
    else
        mv dist/nelux1nject0r /usr/local/bin/
    fi

    # Clean up build artifacts
    rm -rf build/ dist/ nelux1nject0r.spec

    echo -e "${GREEN}[+] Installation complete!${NC}"
    echo -e "${GREEN}[+] You can now run the tool from anywhere with: ${CYAN}nelux1nject0r -h${NC}"
else
    echo -e "${RED}[!] Build failed. PyInstaller did not produce the expected binary.${NC}"
    exit 1
fi
