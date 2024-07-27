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

# Logging configuration
logging.basicConfig(filename="/var/log/idps.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Fetch configuration from the database
try:
    config = Config.objects.first()
    if not config:
        config = Config.objects.create()
    logging.info("Configuration successfully fetched or created from the database.")
except Exception as e:
    logging.error(f"Failed to fetch or create configuration: {str(e)}")
    sys.exit(1)

# Thresholds and attack data storage
FLOOD_THRESHOLD = config.th_flood
SSH_BRUTE_FORCE_THRESHOLD = config.th_ssh
WHITELISTED_SSH_THRESHOLD = config.wl_ssh
WHITELISTED_FLOOD_THRESHOLD = config.wl_flood

ssh_brute_force = defaultdict(int)
flood_detection = defaultdict(lambda: {"count": 0, "time": 0, "last_logged": 0})
LOG_INTERVAL = 60  # Log flood attack interval in seconds

def save_log(message, ip, service):
    IDPSLog.objects.create(service=service, message=message, ip=ip)

def save_blocked_ip(ip, service):
    BannedIP.objects.create(service=service, ip=ip)

def save_successful_login(ip, user, port, protocol):
    log = IDPSLog.objects.create(service=protocol, message=f"Successful SSH login from {ip}", ip=ip)
    SSHSuccess.objects.create(id_idpslog=log, protocol=protocol, user_login=user, port=port, ip=ip)

def ip_already_blocked(ip):
    try:
        subprocess.check_call(["sudo","iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False

def block_ip(ip, service):
    # Bypass IPs in WhiteList
    if WhiteList.objects.filter(ip=ip).exists():
        logging.info(f"IP {ip} is whitelisted, skipping block.")
        save_log(f"IP {ip} is whitelisted, skipping block.", ip, service)
        return
    
    if ip_already_blocked(ip):
        logging.info(f"IP {ip} is already blocked, skipping.")
        return
    
    try:
        subprocess.check_call(["sudo","iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        logging.info(f"IP {ip} has been blocked.")
        save_log(f"IP {ip} has been blocked.", ip, service)
        save_blocked_ip(ip, service)
        save_iptables_rules()
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to block IP {ip}: {str(e)}")
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

        # Get additional information from the packet header
        ttl = packet[IP].ttl
        tos = packet[IP].tos

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

        # Check if IP is whitelisted and exceeds the whitelisted flood threshold
        if WhiteList.objects.filter(ip=ip_src).exists():
            if flood_detection[ip_src]["count"] > WHITELISTED_FLOOD_THRESHOLD:
                logging.info(f"Suspicious {service} flood activity detected from whitelisted IP {ip_src}. TTL: {ttl}, ToS: {tos}")
                save_log(f"Suspicious {service} flood activity detected", ip_src, service)
        else:
            # If an attack is detected for non-whitelisted IP
            if flood_detection[ip_src]["count"] > FLOOD_THRESHOLD:
                # Check if log for this flood attack has been recorded within a certain interval
                if current_time - flood_detection[ip_src]["last_logged"] > LOG_INTERVAL:
                    logging.info(f"{service} Flood attack detected from {ip_src}. TTL: {ttl}, ToS: {tos}")
                    save_log(f"{service} Flood attack detected", ip_src, service)
                    flood_detection[ip_src]["last_logged"] = current_time
                
                block_ip(ip_src, service)
                # Reset count after blocking
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
                    # Log suspicious activity for whitelisted IP
                    ssh_brute_force[ip] += 1
                    if ssh_brute_force[ip] > WHITELISTED_SSH_THRESHOLD:
                        logging.info(f"Suspicious Failed SSH login attempts from whitelisted IP {ip} to {user} using port {port}, protocol {protocol}.")
                        save_log(f"Suspicious Failed SSH login attempts from whitelisted IP {ip}", ip, protocol)
                    continue
                ssh_brute_force[ip] += 1
                logging.info(f"Failed SSH login attempt from {ip} to {user} using port {port}, protocol {protocol}.")
                save_log(f"Failed SSH login attempt from {ip}", ip, protocol)

                if ssh_brute_force[ip] > SSH_BRUTE_FORCE_THRESHOLD:
                    block_ip(ip, protocol)
                    ssh_brute_force[ip] = 0
            elif "Accepted password" in line or "Accepted publickey" in line:
                ip = line.split()[-4]
                user = line.split()[6]
                port = line.split()[-2]
                protocol = line.split()[-1]
                if WhiteList.objects.filter(ip=ip).exists():
                    logging.info(f"Successful SSH login from whitelisted IP {ip} to {user} using port {port}, protocol {protocol}.")
                else:
                    logging.info(f"Successful SSH login from {ip} using port {port} for {user}, protocol {protocol}.")
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
