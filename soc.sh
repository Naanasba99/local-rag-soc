#!/bin/bash

LOG_DIR="/var/soc/logs"

echo "🔥 SOC Terminal Online – Surveillance en temps réel"
echo "-----------------------------------------------------"
echo "1) Surveillance des logs"
echo "2) Analyse brute-force"
echo "3) Détection reconnaissance"
echo "4) Process suspects"
echo "5) Connexions réseau"
echo "6) Analyse complète"
echo "7) Quitter"
echo "-----------------------------------------------------"

surveillance_logs() {
  echo "[+] Surveillance en temps réel..."
  sudo tail -Fn100 $LOG_DIR/*.log
}

bruteforce_detection() {
  echo "[+] Détection brute-force SSH"
  sudo grep "Failed password" -n $LOG_DIR/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr
}

recon_detection() {
  echo "[+] Détection reconnaissance réseau"
  sudo grep -E "Nmap|masscan|zgrab" -n $LOG_DIR/* 2>/dev/null
}

process_suspects() {
  echo "[+] Process suspects"
  ps aux | grep -Ei "nc|ncat|python|perl|meterpreter|reverse|bind" --color=always
}

network_connections() {
  echo "[+] Connexions réseau"
  netstat -an | grep -E "(LISTEN|ESTABLISHED)" | grep -v localhost
}

analyse_complete() {
  echo "⚡ Analyse complète SOC en cours..."
  echo "---- FAILED LOGIN SSH ----"
  bruteforce_detection

  echo "---- PROCESS SUSPECTS ----"
  process_suspects

  echo "---- NETWORK CONNECTIONS ----"
  network_connections

  echo "---- RECON DETECTED ----"
  recon_detection

  echo "Analyse complète terminée."
}

while true; do
  echo ""
  read -p "[CHOIX] > " choice
  case $choice in
    1) surveillance_logs ;;
    2) bruteforce_detection ;;
    3) recon_detection ;;
    4) process_suspects ;;
    5) network_connections ;;
    6) analyse_complete ;;
    7) exit ;;
    *) echo "Choix invalide." ;;
  esac
done

