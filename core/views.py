from django.shortcuts import render, redirect, get_object_or_404
from .models import *
from django.views.generic import ListView, TemplateView
import json
import logging
import subprocess
from subprocess import CalledProcessError
from django.http import JsonResponse
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.contrib.auth.mixins import LoginRequiredMixin

# Konfigurasi logging ke file /var/log/idps.log
logger = logging.getLogger('SafeNetDashboard')
logger.setLevel(logging.INFO)
handler = logging.FileHandler('/var/log/idps.log')
formatter = logging.Formatter('%(asctime)s - SafeNetDashboard - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

def ip_already_blocked(ip, service):
    try:
        IDPSAction(ip, service, "-C", "DROP") 
        return True
    except subprocess.CalledProcessError:
        return False

def IDPSAction(ip, service, action, group):
    if service == "all":
        return subprocess.check_call(["sudo", "iptables", action, "INPUT", "-s", ip, "-j", group], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif service == "TCP":
        return subprocess.check_call(["sudo", "iptables", action, "INPUT", "-s", ip, "-p", "tcp", "-j", group], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif service == "UDP":
        return subprocess.check_call(["sudo", "iptables", action, "INPUT", "-s", ip, "-p", "udp", "-j", group], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif service == "ICMP":
        return subprocess.check_call(["sudo", "iptables", action, "INPUT", "-s", ip, "-p", "icmp", "-j", group], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif service == "SSH":
        return subprocess.check_call(["sudo", "iptables", action, "INPUT", "-s", ip, "-p", "tcp", "--dport", "22", "-j", group], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        pass

class IndexView(ListView):
    model = IDPSLog
    context_object_name = 'idpslog'
    ordering = ['-tanggal', '-waktu']
    template_name = "index.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["title"] = "Home"
        context["banned_count"] = BannedIP.objects.count()
        context["success_count"] = SSHSuccess.objects.count()
        context["white_count"] = WhiteList.objects.count()
        return context

class SSHSuccessView(ListView):
    model = SSHSuccess
    context_object_name = 'sshsuccess'
    template_name = "sshsuccess.html"
    ordering = ['-tanggal', '-waktu']

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["title"] = "SSH Success"
        return context

@method_decorator(csrf_exempt, name='dispatch')
class ConfigView(LoginRequiredMixin, TemplateView):
    template_name = "config.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["title"] = "Config"
        config = Config.objects.first()
        context["config"] = config
        return context

    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)
        button_type = data.get('button_type')
        if button_type == 'enable':
            logger.info("Enable button clicked")
            enable_service()
            active = True
        elif button_type == 'disable':
            logger.info("Disable button clicked")
            disable_service()
            active = False
        return JsonResponse({'status': 'success', 'active': active})

def updateConfig(request, pk):
    config = get_object_or_404(Config, id=pk)

    if request.method == "POST":
        th_ssh = request.POST.get('th_ssh')
        th_flood = request.POST.get('th_flood')
        wl_ssh = request.POST.get('wl_ssh')
        wl_flood = request.POST.get('wl_flood')

        if th_ssh and th_flood and wl_ssh and wl_flood:
            try:
                config.th_ssh = int(th_ssh)
                config.th_flood = int(th_flood)
                config.wl_ssh = int(wl_ssh)
                config.wl_flood = int(wl_flood)
                config.save()
                messages.success(request, "Konfigurasi berhasil diperbarui.")
                logger.info(f"Update config for Flood Threshold {th_flood} white list: {wl_ssh} and SSH Threshold {th_ssh} white list {wl_flood}")
                return redirect('config')
            except ValueError:
                messages.error(request, "Konfigurasi gagal diperbarui.")
                logger.error("Failed to update config for Flood Threshold and SSH Threshold")
                return
        else:
            messages.error(request, "Pastikan semua data telah terisi.")
            return redirect('config')

class BannedIpView(ListView):
    template_name = "bannedip.html"
    model = BannedIP
    context_object_name = "bannedip"
    ordering = ['-tanggal', '-waktu']

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["title"] = "Banned Ip"
        return context

    def post(self, request, *args, **kwargs):
        ip = request.POST.get('ip', '')
        service = request.POST.get('service', '')

        try:
            IDPSAction(ip, service, "-A", "DROP")
            BannedIP.objects.create(service=service, ip=ip)
            messages.success(request, "Banned IP berhasil ditambahkan.")
            logger.info(f"Success to add Banned IP {ip} service {service}")
        except CalledProcessError as e:
            messages.error(request, "Banned IP gagal ditambahkan.")
            logger.error(f"Failed to add Banned IP {ip} service {service}")

        queryset = self.get_queryset()
        context = self.get_context_data(object_list=queryset)
        return render(request, self.template_name, context)

def deleteBannedIp(request, pk):
    try:
        bannedip = BannedIP.objects.get(pk=pk)
        ip = bannedip.ip
        service = bannedip.service
        IDPSAction(ip, service, "-D", "DROP")
        bannedip.delete()
        messages.success(request, "Banned IP berhasil dihapus.")
        logger.info(f"Success to delete Banned IP {ip} service {service}")
    except CalledProcessError as e:
        logger.error(f"Failed to delete iptables rule for {ip}: {str(e)}")
        logger.error(f"Failed to delete Banned IP {ip} service {service}")
        messages.error(request, "Banned IP gagal dihapus.")
    return redirect('bannedip')

class WhiteListView(ListView):
    template_name = "whitelist.html"
    model = WhiteList
    context_object_name = "whitelist"
    ordering = ['-tanggal', '-waktu']

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["title"] = "Whitelist"
        return context

    def post(self, request, *args, **kwargs):
        ip = request.POST.get('ip', '')
        service = request.POST.get('service', '')

        try:
            if ip_already_blocked(ip, service):
                IDPSAction(ip, service, "-D", "DROP")
                IDPSAction(ip, service, "-A", "ACCEPT")
                logger.info(f"IP {ip} is blocked, delete from Banned IP.")
            else:
                IDPSAction(ip, service, "-A", "ACCEPT")
                logger.info(f"Success add Whitelist {ip} for {service}")
        except CalledProcessError as e:
            logger.error(f"Failed to add Whitelist {ip} for {service}")
            logger.error(f"Failed to add iptables rule for {ip}: {str(e)}")

        WhiteList.objects.create(service=service, ip=ip)
        messages.success(request, "White IP berhasil ditambahkan.")
        queryset = self.get_queryset()
        context = self.get_context_data(object_list=queryset)
        return render(request, self.template_name, context)

def deleteWhiteList(request, pk):
    try:
        whitelist = WhiteList.objects.get(pk=pk)
        ip = whitelist.ip
        service = whitelist.service
        IDPSAction(ip, service, "-D", "ACCEPT")
        whitelist.delete()
        messages.success(request, "White IP berhasil dihapus.")
        logger.info(f"Success to delete Whitelist for {ip} service {service}")
    except CalledProcessError as e:
        logger.error(f"Failed to delete iptables rule for {ip}: {str(e)}")
        logger.error(f"Failed to delete Whitelist {ip} for {service}")
        messages.error(request, "White IP gagal dihapus.")
    return redirect('whitelist')

def enable_service():
    try:
        command = ['sudo', 'systemctl', 'enable', '--now', 'idps.service']
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        logger.info("Successfully enabled idps.service: " + result.stdout)
    except subprocess.CalledProcessError as e:
        logger.error("Failed to enable idps.service: " + str(e))
        raise

def disable_service():
    try:
        command = ['sudo', 'systemctl', 'disable', '--now', 'idps.service']
        subprocess.check_call(["sudo", "netfilter-persistent", "save"])
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        logger.info("Successfully disabled idps.service: " + result.stdout)
    except subprocess.CalledProcessError as e:
        logger.error("Failed to disable idps.service: " + str(e))
        raise
