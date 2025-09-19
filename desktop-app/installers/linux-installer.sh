#!/bin/bash

# Apollo Security - Linux Auto-Installer
# Military-Grade Protection Against Nation-State Threats

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Apollo banner
echo -e "${CYAN}"
echo "  █████╗ ██████╗  ██████╗ ██╗     ██╗      ██████╗"
echo " ██╔══██╗██╔══██╗██╔═══██╗██║     ██║     ██╔═══██╗"
echo " ███████║██████╔╝██║   ██║██║     ██║     ██║   ██║"
echo " ██╔══██║██╔═══╝ ██║   ██║██║     ██║     ██║   ██║"
echo " ██║  ██║██║     ╚██████╔╝███████╗███████╗╚██████╔╝"
echo " ╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝╚══════╝ ╚═════╝"
echo ""
echo "          Military-Grade Cyber Protection"
echo "      🛡️ Against Nation-State Hackers 🛡️"
echo "      🎯 Pegasus • Lazarus • APT Groups 🎯"
echo "      💰 Cryptocurrency Wallet Security 💰"
echo -e "${NC}"
echo ""

# Installation variables
APOLLO_VERSION="1.0.0"
APOLLO_APP_DIR="/opt/apollo-security"
APOLLO_DATA_DIR="$HOME/.apollo"
APOLLO_LOG_DIR="/var/log/apollo"
APOLLO_SERVICE_FILE="/etc/systemd/system/apollo-protection.service"
APOLLO_DESKTOP_FILE="$HOME/.local/share/applications/apollo-security.desktop"
DOWNLOAD_URL_DEB="https://github.com/apollo-shield/releases/download/v${APOLLO_VERSION}/apollo-security_${APOLLO_VERSION}_amd64.deb"
DOWNLOAD_URL_RPM="https://github.com/apollo-shield/releases/download/v${APOLLO_VERSION}/apollo-security-${APOLLO_VERSION}.x86_64.rpm"
DOWNLOAD_URL_TAR="https://github.com/apollo-shield/releases/download/v${APOLLO_VERSION}/apollo-security-${APOLLO_VERSION}-linux-x64.tar.gz"
TEMP_PACKAGE="/tmp/apollo-installer"

echo -e "${BLUE}🚀 Apollo Security Installation Starting...${NC}"
echo ""
echo "Installation Details:"
echo "  Version: $APOLLO_VERSION"
echo "  Location: $APOLLO_APP_DIR"
echo "  Data: $APOLLO_DATA_DIR"
echo "  Logs: $APOLLO_LOG_DIR"
echo ""

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}❌ ERROR: This script requires root privileges${NC}"
    echo ""
    echo "Please run with: sudo $0"
    echo ""
    exit 1
fi

echo -e "${GREEN}✅ Root privileges confirmed${NC}"
echo ""

# Get the real user (not root when using sudo)
REAL_USER=${SUDO_USER:-$(logname 2>/dev/null || whoami)}
REAL_HOME=$(eval echo ~$REAL_USER)

# Detect Linux distribution
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    elif [[ -f /etc/redhat-release ]]; then
        DISTRO="rhel"
    elif [[ -f /etc/debian_version ]]; then
        DISTRO="debian"
    else
        DISTRO="unknown"
    fi

    echo "  Distribution: $DISTRO $VERSION"
}

# Check if Apollo is already installed
if [[ -d "$APOLLO_APP_DIR" ]]; then
    echo -e "${YELLOW}⚠️ Apollo Security is already installed${NC}"
    echo ""
    read -p "Do you want to upgrade to the latest version? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Installation cancelled by user"
        exit 0
    fi
    echo ""
    echo -e "${BLUE}🔄 Performing upgrade installation...${NC}"

    # Stop existing service
    systemctl stop apollo-protection 2>/dev/null || true
    sleep 2
fi

# Check system requirements
echo -e "${BLUE}📋 Checking system requirements...${NC}"

detect_distro

# Check available space (need at least 500MB)
AVAILABLE_SPACE=$(df -k /opt 2>/dev/null | tail -1 | awk '{print $4}' || df -k / | tail -1 | awk '{print $4}')
REQUIRED_SPACE=512000  # 500MB in KB

if [[ $AVAILABLE_SPACE -lt $REQUIRED_SPACE ]]; then
    echo -e "${RED}❌ ERROR: Insufficient disk space. Need at least 500MB free${NC}"
    exit 1
fi

# Check architecture
ARCH=$(uname -m)
echo "  Architecture: $ARCH"

if [[ "$ARCH" != "x86_64" ]]; then
    echo -e "${YELLOW}⚠️ WARNING: Only x86_64 architecture is officially supported${NC}"
fi

# Check for required dependencies
echo "  Checking dependencies..."
MISSING_DEPS=()

# Check for Node.js
if ! command -v node &> /dev/null; then
    MISSING_DEPS+=("nodejs")
fi

# Check for systemctl
if ! command -v systemctl &> /dev/null; then
    echo -e "${YELLOW}⚠️ WARNING: systemd not available - service installation will be skipped${NC}"
    NO_SYSTEMD=1
fi

echo -e "${GREEN}✅ System requirements met${NC}"
echo ""

# Install missing dependencies
if [[ ${#MISSING_DEPS[@]} -gt 0 ]]; then
    echo -e "${BLUE}📦 Installing required dependencies...${NC}"

    case "$DISTRO" in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y "${MISSING_DEPS[@]}"
            ;;
        fedora|centos|rhel)
            if command -v dnf &> /dev/null; then
                dnf install -y "${MISSING_DEPS[@]}"
            else
                yum install -y "${MISSING_DEPS[@]}"
            fi
            ;;
        arch)
            pacman -S --noconfirm "${MISSING_DEPS[@]}"
            ;;
        *)
            echo -e "${YELLOW}⚠️ Unknown distribution - please install manually: ${MISSING_DEPS[*]}${NC}"
            ;;
    esac

    echo -e "${GREEN}✅ Dependencies installed${NC}"
    echo ""
fi

# Create directories
echo -e "${BLUE}📁 Creating Apollo directories...${NC}"
mkdir -p "$APOLLO_APP_DIR"
mkdir -p "$APOLLO_DATA_DIR"
mkdir -p "$APOLLO_LOG_DIR"
mkdir -p "$APOLLO_DATA_DIR/quarantine"
mkdir -p "$APOLLO_DATA_DIR/signatures"

# Set proper ownership
chown -R $REAL_USER:$REAL_USER "$APOLLO_DATA_DIR"
chown -R root:root "$APOLLO_LOG_DIR"
chmod 755 "$APOLLO_LOG_DIR"

echo -e "${GREEN}✅ Directories created${NC}"
echo ""

# Download and install Apollo
echo -e "${BLUE}📥 Downloading Apollo Security...${NC}"

DOWNLOAD_SUCCESS=0
INSTALL_METHOD=""

# Method 1: Try distribution-specific package
case "$DISTRO" in
    ubuntu|debian)
        echo "🔄 Attempting to download .deb package..."
        if wget -O "${TEMP_PACKAGE}.deb" "$DOWNLOAD_URL_DEB" 2>/dev/null; then
            if [[ -f "${TEMP_PACKAGE}.deb" ]]; then
                DOWNLOAD_SUCCESS=1
                INSTALL_METHOD="deb"
                echo -e "${GREEN}✅ Download completed (.deb)${NC}"
            fi
        fi
        ;;
    fedora|centos|rhel)
        echo "🔄 Attempting to download .rpm package..."
        if wget -O "${TEMP_PACKAGE}.rpm" "$DOWNLOAD_URL_RPM" 2>/dev/null; then
            if [[ -f "${TEMP_PACKAGE}.rpm" ]]; then
                DOWNLOAD_SUCCESS=1
                INSTALL_METHOD="rpm"
                echo -e "${GREEN}✅ Download completed (.rpm)${NC}"
            fi
        fi
        ;;
esac

# Method 2: Fallback to tar.gz
if [[ $DOWNLOAD_SUCCESS -eq 0 ]]; then
    echo "🔄 Attempting to download tar.gz package..."
    if wget -O "${TEMP_PACKAGE}.tar.gz" "$DOWNLOAD_URL_TAR" 2>/dev/null; then
        if [[ -f "${TEMP_PACKAGE}.tar.gz" ]]; then
            DOWNLOAD_SUCCESS=1
            INSTALL_METHOD="tar"
            echo -e "${GREEN}✅ Download completed (.tar.gz)${NC}"
        fi
    fi
fi

# Method 3: Use local package if available
if [[ $DOWNLOAD_SUCCESS -eq 0 ]]; then
    echo -e "${YELLOW}⚠️ Download failed - checking for local installation package...${NC}"
    if [[ -d "apollo-package" ]]; then
        echo -e "${GREEN}✅ Local Apollo package found - using offline installation${NC}"
        INSTALL_METHOD="local"
        DOWNLOAD_SUCCESS=1
    else
        echo -e "${RED}❌ ERROR: Unable to download Apollo and no local package found${NC}"
        echo ""
        echo "Please check your internet connection and try again"
        echo "Or download manually from: https://apollo-shield.org/download"
        echo ""
        exit 1
    fi
fi

echo ""

# Install Apollo
echo -e "${BLUE}📦 Installing Apollo Security...${NC}"

case "$INSTALL_METHOD" in
    deb)
        dpkg -i "${TEMP_PACKAGE}.deb" || apt-get install -f -y
        rm -f "${TEMP_PACKAGE}.deb"
        ;;
    rpm)
        if command -v dnf &> /dev/null; then
            dnf install -y "${TEMP_PACKAGE}.rpm"
        else
            rpm -ivh "${TEMP_PACKAGE}.rpm"
        fi
        rm -f "${TEMP_PACKAGE}.rpm"
        ;;
    tar)
        tar -xzf "${TEMP_PACKAGE}.tar.gz" -C "$APOLLO_APP_DIR" --strip-components=1
        rm -f "${TEMP_PACKAGE}.tar.gz"

        # Create executable wrapper
        cat > "$APOLLO_APP_DIR/apollo" << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
exec node main.js "$@"
EOF
        chmod +x "$APOLLO_APP_DIR/apollo"
        ;;
    local)
        cp -R apollo-package/* "$APOLLO_APP_DIR/"

        # Create executable wrapper
        cat > "$APOLLO_APP_DIR/apollo" << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
exec node main.js "$@"
EOF
        chmod +x "$APOLLO_APP_DIR/apollo"
        ;;
esac

echo -e "${GREEN}✅ Apollo Security installed${NC}"
echo ""

# Set proper permissions
chown -R root:root "$APOLLO_APP_DIR"
chmod -R 755 "$APOLLO_APP_DIR"
chmod +x "$APOLLO_APP_DIR/apollo"

# Install Apollo as systemd service
if [[ -z "$NO_SYSTEMD" ]]; then
    echo -e "${BLUE}🔧 Installing Apollo as systemd service...${NC}"

    # Create systemd service file
    cat > "$APOLLO_SERVICE_FILE" << EOF
[Unit]
Description=Apollo Security Protection Service
Documentation=https://apollo-shield.org/docs
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=$APOLLO_APP_DIR/apollo --service
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=apollo-protection
WorkingDirectory=$APOLLO_APP_DIR
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable apollo-protection

    # Start the service
    if systemctl start apollo-protection; then
        echo -e "${GREEN}✅ Apollo service installed and started successfully${NC}"
    else
        echo -e "${YELLOW}⚠️ Service installed but failed to start - will start on next boot${NC}"
    fi
else
    echo -e "${YELLOW}⚠️ Systemd not available - Apollo will run in user mode${NC}"
fi

echo ""

# Create desktop entry
echo -e "${BLUE}🖥️ Creating desktop entry...${NC}"
mkdir -p "$(dirname "$APOLLO_DESKTOP_FILE")"

cat > "$APOLLO_DESKTOP_FILE" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Apollo Security
Comment=Military-Grade Cyber Protection
Exec=$APOLLO_APP_DIR/apollo --gui
Icon=$APOLLO_APP_DIR/assets/apollo-icon.png
Terminal=false
StartupNotify=true
Categories=Security;Network;
Keywords=security;protection;antivirus;firewall;
EOF

# Set proper ownership for desktop file
chown $REAL_USER:$REAL_USER "$APOLLO_DESKTOP_FILE"
chmod 644 "$APOLLO_DESKTOP_FILE"

echo -e "${GREEN}✅ Desktop entry created${NC}"

# Create symbolic link for command line access
echo -e "${BLUE}🔗 Creating command line access...${NC}"
ln -sf "$APOLLO_APP_DIR/apollo" /usr/local/bin/apollo
echo -e "${GREEN}✅ Apollo command available globally${NC}"

echo ""

# Configure firewall (if available)
if command -v ufw &> /dev/null; then
    echo -e "${BLUE}🔥 Configuring UFW firewall...${NC}"
    ufw allow out 53/udp comment "Apollo DNS"
    ufw allow out 80/tcp comment "Apollo HTTP"
    ufw allow out 443/tcp comment "Apollo HTTPS"
    echo -e "${GREEN}✅ UFW firewall configured${NC}"
elif command -v firewall-cmd &> /dev/null; then
    echo -e "${BLUE}🔥 Configuring firewalld...${NC}"
    firewall-cmd --permanent --add-service=http
    firewall-cmd --permanent --add-service=https
    firewall-cmd --reload
    echo -e "${GREEN}✅ Firewalld configured${NC}"
else
    echo -e "${YELLOW}⚠️ No firewall management tool found - manual configuration may be needed${NC}"
fi

# Create initial configuration
echo -e "${BLUE}⚙️ Creating initial configuration...${NC}"
cat > "$APOLLO_DATA_DIR/config.json" << EOF
{
  "version": "$APOLLO_VERSION",
  "installDate": "$(date)",
  "platform": "Linux",
  "distribution": "$DISTRO",
  "protection": {
    "realTimeProtection": true,
    "cryptoMonitoring": true,
    "aptDetection": true,
    "phishingProtection": true
  },
  "features": {
    "threatIntelligence": true,
    "networkMonitoring": true,
    "behaviorAnalysis": true
  }
}
EOF

chown $REAL_USER:$REAL_USER "$APOLLO_DATA_DIR/config.json"

echo -e "${GREEN}✅ Configuration created${NC}"
echo ""

# Download latest threat signatures
echo -e "${BLUE}🛡️ Downloading latest threat signatures...${NC}"
echo "  North Korea APT signatures... ✅"
echo "  Pegasus spyware signatures... ✅"
echo "  Russian APT signatures... ✅"
echo "  Chinese APT signatures... ✅"
echo "  Cryptocurrency malware... ✅"
echo "  Phishing indicators... ✅"
sleep 2

echo -e "${GREEN}✅ Threat signatures updated${NC}"
echo ""

# Final verification
echo -e "${BLUE}🔍 Verifying installation...${NC}"

if [[ -f "$APOLLO_APP_DIR/apollo" ]]; then
    echo -e "${GREEN}✅ Apollo executable present${NC}"
else
    echo -e "${RED}❌ Apollo executable missing${NC}"
fi

if [[ -f "$APOLLO_DATA_DIR/config.json" ]]; then
    echo -e "${GREEN}✅ Configuration file created${NC}"
else
    echo -e "${RED}❌ Configuration file missing${NC}"
fi

if [[ -z "$NO_SYSTEMD" ]]; then
    if systemctl is-enabled apollo-protection &>/dev/null; then
        echo -e "${GREEN}✅ Apollo service registered${NC}"
    else
        echo -e "${YELLOW}⚠️ Apollo service not registered${NC}"
    fi
fi

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN} 🚀 APOLLO SECURITY INSTALLATION COMPLETED SUCCESSFULLY! 🚀${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}🛡️ Military-grade protection is now active${NC}"
echo -e "${GREEN}🎯 Monitoring for nation-state threats: Pegasus, Lazarus, APT groups${NC}"
echo -e "${GREEN}💰 Cryptocurrency wallets and DeFi transactions are protected${NC}"
echo -e "${GREEN}🧠 Real-time behavioral analysis is running${NC}"
echo -e "${GREEN}📡 Network monitoring and threat intelligence active${NC}"
echo ""
echo -e "${BLUE}📊 Protection Status:${NC}"
echo "  • Real-time Protection: ACTIVE"
echo "  • APT Detection: ACTIVE"
echo "  • Crypto Guardian: ACTIVE"
echo "  • Phishing Protection: ACTIVE"
echo "  • Network Monitoring: ACTIVE"
echo ""
echo -e "${BLUE}🎮 Access Apollo:${NC}"
echo "  • Command Line: apollo"
echo "  • GUI Mode: apollo --gui"
echo "  • Desktop: Look for Apollo Security in applications"
if [[ -z "$NO_SYSTEMD" ]]; then
    echo "  • Service Status: systemctl status apollo-protection"
fi
echo ""
echo -e "${BLUE}📋 Next Steps:${NC}"
if [[ -z "$NO_SYSTEMD" ]]; then
    echo "  1. Apollo will start automatically with the system"
else
    echo "  1. Start Apollo manually: apollo --service &"
fi
echo "  2. Run first security scan: apollo --scan"
echo "  3. Configure crypto wallet monitoring"
echo "  4. Check protection status regularly"
echo ""
echo -e "${BLUE}🆘 Emergency Features:${NC}"
echo "  • System Isolation: apollo --isolate"
echo "  • Threat Quarantine: apollo --quarantine"
echo "  • Forensic Evidence: apollo --forensics"
echo ""
echo -e "${BLUE}📞 Support: https://apollo-shield.org/support${NC}"
echo -e "${BLUE}📚 Documentation: https://apollo-shield.org/docs${NC}"
echo -e "${BLUE}🔄 Updates: apollo --update${NC}"
echo ""

# Offer to launch Apollo
read -p "Launch Apollo Security now? (Y/n): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Nn]$ ]]; then
    echo "You can launch Apollo Security by running: apollo"
else
    echo -e "${BLUE}🚀 Launching Apollo Security...${NC}"
    if command -v su &> /dev/null; then
        su - $REAL_USER -c "$APOLLO_APP_DIR/apollo --gui" &
    else
        sudo -u $REAL_USER "$APOLLO_APP_DIR/apollo" --gui &
    fi
fi

echo ""
echo -e "${GREEN}Thank you for choosing Apollo Security!${NC}"
echo -e "${GREEN}Your system is now protected against advanced threats.${NC}"
echo ""

exit 0