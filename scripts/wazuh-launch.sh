#!/bin/bash

# ============================================
#   WAZUH PRESENTATION DAY LAUNCHER
#   AIOps Project - Ricky Achoki
# ============================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

clear
echo -e "${CYAN}"
echo "  ██╗    ██╗ █████╗ ███████╗██╗   ██╗██╗  ██╗"
echo "  ██║    ██║██╔══██╗╚══███╔╝██║   ██║██║  ██║"
echo "  ██║ █╗ ██║███████║  ███╔╝ ██║   ██║███████║"
echo "  ██║███╗██║██╔══██║ ███╔╝  ██║   ██║██╔══██║"
echo "  ╚███╔███╔╝██║  ██║███████╗╚██████╔╝██║  ██║"
echo "   ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "${BOLD}  AIOps Project — Presentation Day Launcher${NC}"
echo -e "  ─────────────────────────────────────────"
echo ""

# --- Start Services ---
echo -e "${YELLOW}[1/4]${NC} Starting Wazuh Indexer..."
sudo systemctl start wazuh-indexer
sleep 3

echo -e "${YELLOW}[2/4]${NC} Starting Wazuh Manager..."
sudo systemctl start wazuh-manager
sleep 3

echo -e "${YELLOW}[3/4]${NC} Starting Filebeat..."
sudo systemctl start filebeat
sleep 2

echo -e "${YELLOW}[4/4]${NC} Starting Wazuh Dashboard..."
sudo systemctl start wazuh-dashboard
sleep 5

echo ""
echo -e "  ─────────────────────────────────────────"
echo -e "${BOLD}  SERVICE STATUS${NC}"
echo -e "  ─────────────────────────────────────────"

# Check each service
services=("wazuh-indexer" "wazuh-manager" "filebeat" "wazuh-dashboard")
all_good=true

for service in "${services[@]}"; do
    status=$(systemctl is-active $service)
    if [ "$status" == "active" ]; then
        echo -e "  ${GREEN}●${NC} $service — ${GREEN}RUNNING${NC}"
    else
        echo -e "  ${RED}●${NC} $service — ${RED}$status${NC}"
        all_good=false
    fi
done

echo ""
echo -e "  ─────────────────────────────────────────"
echo -e "${BOLD}  DASHBOARD CREDENTIALS${NC}"
echo -e "  ─────────────────────────────────────────"
echo -e "  🌐 URL:      ${CYAN}https://localhost${NC}"
echo -e "  👤 Username: ${CYAN}admin${NC}"
echo -e "  🔑 Password: ${CYAN}[your password here]${NC}"
echo -e "  ─────────────────────────────────────────"
echo ""

if $all_good; then
    echo -e "  ${GREEN}${BOLD}✓ All systems GO! Open your browser at https://localhost${NC}"
    # Auto-open browser
    xdg-open https://localhost 2>/dev/null &
else
    echo -e "  ${RED}${BOLD}⚠ Some services failed. Check logs: sudo journalctl -u wazuh-manager -n 50${NC}"
fi

echo ""
