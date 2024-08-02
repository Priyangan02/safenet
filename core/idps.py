import logging
import subprocess
import time
from collections import defaultdict
import signal
import sys
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP
import django
from django.conf import settings
import os
from bot import send_telegram_message

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'safenet.settings')
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
django.setup()

from core.models import IDPSLog, BannedIP, WhiteList, SSHSuccess, Config

logger = logging.getLogger('SafeNetIDPS')
logger.setLevel(logging.INFO)
handler = logging.FileHandler('/var/log/idps.log')
formatter = logging.Formatter('%(asctime)s - SafeNet - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

try:
    config = Config.objects.first()
    if not config:
        config = Config.objects.create()
    logger.info("Configuration successfully fetched or created from the database.")
except Exception as e:
    logger.error(f"Failed to fetch or create configuration: {str(e)}")
    sys.exit(1)

FLOOD_THRESHOLD = config.th_flood
SSH_BRUTE_FORCE_THRESHOLD = config.th_ssh
WHITELISTED_SSH_THRESHOLD = config.wl_ssh
WHITELISTED_FLOOD_THRESHOLD = config.wl_flood

ssh_brute_force = defaultdict(lambda: {"count": 0, "last_logged": 0})
flood_detection = defaultdict(lambda: {"count": 0, "time": 0, "last_logged": 0, "services": set()})
LOG_INTERVAL = 60
SUSPICIOUS_LOG_INTERVAL = 300

def save_log(message, ip, service):
    IDPSLog.objects.create(service=service, message=message, ip=ip)

def save_blocked_ip(ip, service):
    BannedIP.objects.create(service=service, ip=ip)

def save_successful_login(ip, user, port, service):
    log = IDPSLog.objects.create(service=service, message=f"Successful SSH login from {ip}", ip=ip)
    SSHSuccess.objects.create(id_idpslog=log, service=service, user_login=user, port=port, ip=ip)

def ip_already_blocked(ip, service):
    try:
        output = subprocess.check_output(["sudo", "iptables", "-L", "-n"], stderr=subprocess.PIPE).decode()
        if any(ip in line and service.lower() in line.lower() and "DROP" in line for line in output.splitlines()):
            return True
        return False
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to check if IP {ip} is blocked: {str(e)}")
        return False

def block_ip(ip, service):
    if WhiteList.objects.filter(ip=ip).exists():
        logger.info(f"IP {ip} is whitelisted, skipping block.")
        save_log(f"IP {ip} is whitelisted, skipping block.", ip, service)
        return

    if ip_already_blocked(ip, service):
        logger.info(f"IP {ip} is already blocked for {service}, skipping.")
        return

    try:
        if service == "TCP":
            subprocess.check_call(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-p", "tcp", "-j", "DROP"])
        elif service == "UDP":
            subprocess.check_call(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-p", "udp", "-j", "DROP"])
        elif service == "ICMP":
            subprocess.check_call(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-p", "icmp", "-j", "DROP"])
        elif service == "SSH":
            subprocess.check_call(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-p", "tcp", "--dport", "22", "-j", "DROP"])

        logger.info(f"IP {ip} has been blocked for {service}.")
        save_log(f"IP {ip} has been blocked for {service}.", ip, service)
        send_telegram_message(f"IP {ip} has been blocked for {service}.")
        save_blocked_ip(ip, service)
        save_iptables_rules()
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to block IP {ip} for {service}: {str(e)}")
        save_log(f"Failed to block IP {ip} for {service}: {str(e)}", ip, service)

def save_iptables_rules():
    try:
        subprocess.check_call(["sudo", "netfilter-persistent", "save"])
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to save iptables rules: {str(e)}")

def restore_iptables_rules():
    try:
        subprocess.check_call(["sudo", "netfilter-persistent", "reload"])
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to restore iptables rules: {str(e)}")

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ttl = packet[IP].ttl
        tos = packet[IP].tos
        current_time = time.time()
        service = None

        if packet.haslayer(TCP):
            flood_detection[ip_src]["count"] += 1
            flood_detection[ip_src]["time"] = current_time
            service = "TCP"
            flood_detection[ip_src]["services"].add(service)
        elif packet.haslayer(UDP):
            flood_detection[ip_src]["count"] += 1
            flood_detection[ip_src]["time"] = current_time
            service = "UDP"
            flood_detection[ip_src]["services"].add(service)
        elif packet.haslayer(ICMP):
            icmp_type = packet[ICMP].type
            if icmp_type == 8:
                flood_detection[ip_src]["count"] += 1
                flood_detection[ip_src]["time"] = current_time
                service = "ICMP"
                flood_detection[ip_src]["services"].add(service)

        if WhiteList.objects.filter(ip=ip_src).exists():
            if flood_detection[ip_src]["count"] > WHITELISTED_FLOOD_THRESHOLD:
                if current_time - flood_detection[ip_src]["last_logged"] > SUSPICIOUS_LOG_INTERVAL:
                    logger.info(f"Suspicious {service} flood activity detected from whitelisted IP {ip_src}. TTL: {ttl}, ToS: {tos}")
                    send_telegram_message(f"Suspicious {service} flood activity detected from whitelisted IP {ip_src}.")
                    save_log(f"Suspicious {service} flood activity detected", ip_src, service)
                    flood_detection[ip_src]["last_logged"] = current_time
        else:
            if flood_detection[ip_src]["count"] > FLOOD_THRESHOLD:
                if current_time - flood_detection[ip_src]["last_logged"] > LOG_INTERVAL:
                    logger.info(f"{service} Flood attack detected from {ip_src}. TTL: {ttl}, ToS: {tos}")
                    send_telegram_message(f"{service} Flood attack detected from {ip_src}.")
                    save_log(f"{service} Flood attack detected", ip_src, service)
                    flood_detection[ip_src]["last_logged"] = current_time
                    block_ip(ip_src, service)
                    flood_detection[ip_src] = {"count": 0, "time": 0, "last_logged": flood_detection[ip_src]["last_logged"], "services": flood_detection[ip_src]["services"]}

def monitor_ssh_log():
    ssh_logfile = "/var/log/auth.log"
    with subprocess.Popen(['tail', '-F', ssh_logfile], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
        for line in p.stdout:
            line = line.decode('utf-8')
            ip = None
            user = None
            port = None
            service = None

            logger.debug(f"SSH log line: {line.strip()}")

            if "Failed password" in line:
                ip = line.split()[-4]
                user = line.split()[-6]
                port = line.split()[-2]
                service = "SSH"
                logger.debug(f"Detected failed password attempt from {ip} to {user} using port {port}")
                if WhiteList.objects.filter(ip=ip).exists():
                    ssh_brute_force[ip]["count"] += 1
                    if ssh_brute_force[ip]["count"] > WHITELISTED_SSH_THRESHOLD:
                        if time.time() - ssh_brute_force[ip]["last_logged"] > SUSPICIOUS_LOG_INTERVAL:
                            logger.info(f"Suspicious Failed SSH login attempts from whitelisted IP {ip} to {user} using port {port}.")
                            send_telegram_message(f"Suspicious Failed SSH login attempts from whitelisted IP {ip} to {user} using port {port}.")
                            save_log(f"Suspicious Failed SSH login attempts from whitelisted IP {ip}", ip, service)
                            ssh_brute_force[ip]["last_logged"] = time.time()
                    continue
                ssh_brute_force[ip]["count"] += 1
                if ssh_brute_force[ip]["count"] > SSH_BRUTE_FORCE_THRESHOLD:
                    logger.info(f"SSH Brute Force attack detected from {ip} to {user} using port {port}.")
                    send_telegram_message(f"SSH Brute Force attack detected from {ip} to {user} using port {port}.")
                    save_log(f"SSH Brute Force attack detected", ip, service)
                    block_ip(ip, "SSH")
                    ssh_brute_force[ip]["count"] = 0
                    ssh_brute_force[ip]["last_logged"] = time.time()
            elif "Accepted password" in line:
                ip = line.split()[-4]
                user = line.split()[-6]
                port = line.split()[-2]
                service = "SSH"
                logger.info(f"Successful SSH login from {ip} to {user} using port {port}.")
                send_telegram_message(f"Successful SSH login from {ip} to {user} using port {port}.")
                save_successful_login(ip, user, port, service)

def main():
    logger.info("Starting packet capture and SSH log monitoring.")
    try:
        restore_iptables_rules()
        sniff_thread = threading.Thread(target=lambda: sniff(prn=packet_callback, store=0))
        sniff_thread.start()
        monitor_ssh_log()
    except Exception as e:
        logger.error(f"Error in main function: {str(e)}")
    finally:
        signal.signal(signal.SIGINT, signal_handler)
        signal.pause()

def signal_handler(sig, frame):
    logger.info("Exiting and saving iptables rules.")
    save_iptables_rules()
    sys.exit(0)

if __name__ == "__main__":
    main()
