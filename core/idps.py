import logging
import subprocess
import time
from collections import defaultdict
import signal
import sys
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP
from django.utils import timezone
import django
from django.conf import settings
import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'safenet.settings')

# Add the project directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")

# Initialize Django
django.setup()

from core.models import IDPSLog, BannedIP, WhiteList, SSHSuccess, Config

# Konfigurasi logging
logging.basicConfig(filename="/var/log/idps.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Ambil konfigurasi dari database
try:
    config = Config.objects.first()
    if not config:
        config = Config.objects.create()
    logging.info("Successfully fetched or created configuration from database.")
except Exception as e:
    logging.error(f"Failed to fetch or create config: {str(e)}")
    sys.exit(1)

# Ambang batas dan penyimpanan data serangan
FLOOD_THRESHOLD = config.th_flood
SSH_BRUTE_FORCE_THRESHOLD = config.th_ssh

ssh_brute_force = defaultdict(int)
flood_detection = defaultdict(lambda: {"count": 0, "time": 0, "last_logged": 0})
LOG_INTERVAL = 60  # Interval waktu dalam detik untuk mencatat log flood attack

def save_log(message, ip, service):
    IDPSLog.objects.create(service=service, message=message, ip=ip)

def save_blocked_ip(ip, service):
    BannedIP.objects.create(service=service, ip=ip)

def save_successful_login(ip, user, port, protocol):
    log = IDPSLog.objects.create(service=protocol, message=f"Successful SSH login from {ip}", ip=ip)
    SSHSuccess.objects.create(id_idpslog=log, protocol=protocol, user_login=user, port=port, ip=ip)

def ip_already_blocked(ip):
    try:
        subprocess.check_call(["sudo","iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"])
        return True
    except subprocess.CalledProcessError:
        return False

def block_ip(ip, service):
    # Bypass IPs in WhiteList
    if WhiteList.objects.filter(ip=ip).exists():
        logging.info(f"IP {ip} is in whitelist, skipping block.")
        # Mencatat ke log bahwa IP di whitelist
        save_log(f"IP {ip} is in whitelist, skipping block.", ip, service)
        return
    
    if ip_already_blocked(ip):
        logging.info(f"IP {ip} already blocked, skipping.")
        return
    
    try:
        subprocess.check_call(["sudo","iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        logging.info(f"Blocked IP {ip}")
        save_log(f"Blocked IP {ip}", ip, service)
        save_blocked_ip(ip, service)
        save_iptables_rules()
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to block IP {ip}: {str(e)}")
        # Mencatat ke log bahwa blokir gagal
        save_log(f"Failed to block IP {ip}: {str(e)}", ip, "SSH")

def save_iptables_rules():
    try:
        subprocess.check_call(["sudo", "netfilter-persistent", "save"])
    except subprocess.CalledProcessError as e:
        
        logging.error(f"Failed to save iptables rules: {str(e)}")

def restore_iptables_rules():
    try:
        subprocess.check_call(["sudo", "netfilter-persistent", "reload"])
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to restore iptables rules: {str(e)}")

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src

        # Mendapatkan informasi tambahan dari header paket
        ttl = packet[IP].ttl
        tos = packet[IP].tos

        # Bypass IPs in WhiteList
        if WhiteList.objects.filter(ip=ip_src).exists():
            return

        current_time = time.time()
        service = None

        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            if flags == "S":  # SYN flag
                flood_detection[ip_src]["count"] += 1
                flood_detection[ip_src]["time"] = current_time
                service = "TCP"
        elif packet.haslayer(UDP):
            flood_detection[ip_src]["count"] += 1
            flood_detection[ip_src]["time"] = current_time
            service = "UDP"
        elif packet.haslayer(ICMP):
            icmp_type = packet[ICMP].type
            if icmp_type == 8:  # ICMP Echo Request
                flood_detection[ip_src]["count"] += 1
                flood_detection[ip_src]["time"] = current_time
                service = "ICMP"

        # Jika serangan terdeteksi
        if flood_detection[ip_src]["count"] > FLOOD_THRESHOLD:
            # Cek apakah sudah mencatat log untuk flood attack ini dalam interval waktu tertentu
            if current_time - flood_detection[ip_src]["last_logged"] > LOG_INTERVAL:
                logging.info(f"Flood attack detected from {ip_src}. TTL: {ttl}, ToS: {tos}")
                save_log("Flood attack detected", ip_src, service)
                flood_detection[ip_src]["last_logged"] = current_time
            
            block_ip(ip_src, service)
            # Reset hitungan setelah pemblokiran
            flood_detection[ip_src] = {"count": 0, "time": 0, "last_logged": flood_detection[ip_src]["last_logged"]}

def monitor_ssh_log():
    ssh_logfile = "/var/log/auth.log"
    with subprocess.Popen(['tail', '-F', ssh_logfile], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
        for line in p.stdout:
            line = line.decode('utf-8')
            ip = None
            user = None
            port = None
            protocol = None

            if "Failed password" in line:
                ip = line.split()[-4]
                user = line.split()[-6]
                port = line.split()[-2]
                protocol = line.split()[-1]
                if WhiteList.objects.filter(ip=ip).exists():
                    continue
                ssh_brute_force[ip] += 1
                logging.info(f"Failed SSH login attempt from {ip} to {user} using port {port} protocol {protocol}")
                save_log("Failed SSH login attempt", ip, protocol)

                if ssh_brute_force[ip] > SSH_BRUTE_FORCE_THRESHOLD:
                    block_ip(ip, protocol)
                    ssh_brute_force[ip] = 0
            elif "Accepted password" in line or "Accepted publickey" in line:
                ip = line.split()[-4]
                user = line.split()[6]
                port = line.split()[-2]
                protocol = line.split()[-1]
                if WhiteList.objects.filter(ip=ip).exists():
                    logging.info(f"Successful SSH login from whitelisted IP {ip}to {user} using port {port} protocol {protocol}")
                else:
                    logging.info(f"Successful SSH login from {ip} use port {port} for {user} protocol {protocol}")
                save_successful_login(ip, user, port, protocol)

def main():
    print("Starting packet capture and SSH log monitoring.")
    try:
        restore_iptables_rules()
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("Packet capture stopped.")

def signal_handler(sig, frame):
    print("Stopping IDPS...")
    sys.exit(0)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

threading.Thread(target=monitor_ssh_log, daemon=True).start()

if __name__ == "__main__":
    main()

