from django.shortcuts import render, redirect, get_object_or_404
from .models import *
from django.views.generic import ListView,TemplateView
import json
import logging
from django.contrib.auth.mixins import LoginRequiredMixin
import subprocess
from subprocess import CalledProcessError
from django.http import JsonResponse
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

# Konfigurasi logging
logging.basicConfig(filename="/var/log/idps.log", level=logging.INFO, format="%(asctime)s - %(message)s")

def ip_already_blocked(ip):
    try:
        subprocess.check_call(["sudo","iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"] ,stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False
    
class IndexView(ListView):
    model = IDPSLog
    context_object_name ='idpslog'
    ordering = ['-tanggal','-waktu']
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
    context_object_name ='sshsuccess'
    template_name = "sshsuccess.html"
    ordering = ['-tanggal','-waktu']
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["title"] = "SSH Sussess"
        return context
@method_decorator(csrf_exempt, name='dispatch')
class ConfigView(LoginRequiredMixin,TemplateView):
    template_name = "config.html"
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["title"] = "Config" 
        config = Config.objects.first()  # Misalnya, ambil konfigurasi pertama
        context["config"] = config
        return context

    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)
        button_type = data.get('button_type')
        if button_type == 'enable':
            print("Enable button clicked")
            enable_service()
            active = True
        elif button_type == 'disable':
            disable_service()
            print("Disable button clicked")
            active = False
        return JsonResponse({'status': 'success','active':active})
    
def updateConfig(request, pk):
    config = get_object_or_404(Config, id=pk)
    
    if request.method == "POST":
        th_ssh = request.POST.get('th_ssh')
        th_flood = request.POST.get('th_flood')
        
        # Validasi sederhana
        if th_ssh and th_flood:
            try:
                config.th_ssh = int(th_ssh)
                config.th_flood = int(th_flood)
                config.save()
                messages.success(request, "Konfigurasi berhasil diperbarui.")
                logging.info(f"Update config for Flood Threshold {th_flood} and SSH Threshold {th_ssh}")
                return redirect('config')  # Pastikan ada view config_detail yang sesuai
                
            except ValueError:
                # Tangani kasus jika nilai yang dimasukkan bukan integer
                messages.error(request, "Konfigurasi gagal diperbarui.")
                logging.error(f"Failed to update config for Flood Threshold and SSH Threshold")
                return 
        else:
            messages.error(request, "Pastikan semua data telah terisi.")
            return redirect('config')  # Pastikan ada view config_detail yang sesuai
        
    

class BannedIpView(ListView):
    template_name="bannedip.html"
    model = BannedIP
    context_object_name = "bannedip"
    ordering = ['-tanggal','-waktu']
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["title"] = "Banned Ip"
        return context
    
    def post(self, request, *args, **kwargs):
        # Ambil data POST yang dikirimkan oleh pengguna
        ip = request.POST.get('ip', '')
        service = request.POST.get('service', '')
        # Lakukan sesuatu dengan data POST yang diterima, misalnya simpan ke database
        try:
            subprocess.check_call(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
            BannedIP.objects.create(service=service, ip=ip)
            messages.success(request, "Banned IP berhasil ditambahkan.")
            logging.info(f"Success to add Banned IP {ip} service {service}")
        except CalledProcessError as e:
            # Tangani kesalahan saat perintah iptables gagal
            messages.error(request, "Banned IP gagal ditambahkan.")
            logging.error(f"Failed to add Banned IP {ip} service {service}")
            # Anda bisa menambahkan pesan kesalahan ke context untuk ditampilkan di template

        # Ambil ulang data yang akan ditampilkan dalam ListView setelah penambahan
        queryset = self.get_queryset()
        context = self.get_context_data(object_list=queryset)
        return render(request, self.template_name, context)


def deleteBannedIp(request,pk):
    try:
        bannedip = BannedIP.objects.get(pk=pk)
        ip = bannedip.ip
        service = bannedip.service
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
        bannedip.delete()
        messages.success(request, "Banned IP berhasil dihapus.")
        logging.info(f"Success to detele Banned IP {ip} service {service}")
    except CalledProcessError as e:
        # Tangani kesalahan saat perintah iptables gagal
        logging.error(f"Failed to delete iptables rule for {ip}: {str(e)}")
        logging.error(f"Failed to delete Banned IP {ip} service {service}")
        messages.error(request, "Banned IP gagal dihapus.")
        # Anda bisa menambahkan pesan kesalahan ke context untuk ditampilkan di template
    return redirect('bannedip')
    

class WhiteListView(ListView):
    template_name = "whitelist.html"
    model = WhiteList
    context_object_name = "whitelist"
    ordering = ['-tanggal','-waktu']
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["title"] = "whitelist"
        return context
    def post(self, request, *args, **kwargs):
        # Ambil data POST yang dikirimkan oleh pengguna
        ip = request.POST.get('ip', '')
        service = request.POST.get('service', '')
        
        try:
            if ip_already_blocked(ip):
                subprocess.check_call(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
                subprocess.check_call(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "ACCEPT"])
                logging.info(f"IP {ip} is blocked, delete from Banned IP.")
            else:
                subprocess.check_call(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "ACCEPT"])
                logging.info(f"Success add Whitelist {ip} for {service}")

        except CalledProcessError as e:
            # Tangani kesalahan saat perintah iptables gagal
            logging.error(f"Failed to add Whitelist {ip} for {service}")
            logging.error(f"Failed to add iptables rule for {ip}: {str(e)}")
            # Anda bisa menambahkan pesan kesalahan ke context untuk ditampilkan di template

        # Lakukan sesuatu dengan data POST yang diterima, misalnya simpan ke database
        WhiteList.objects.create(service=service, ip=ip)
        messages.success(request, "White IP berhasil ditambahkan.")
        # Ambil ulang data yang akan ditampilkan dalam ListView setelah penambahan
        queryset = self.get_queryset()
        context = self.get_context_data(object_list=queryset)
        return render(request, self.template_name, context)
    


def deleteWaitList(request,pk):
    try:
        whitelist = WhiteList.objects.get(pk=pk)    
        ip = whitelist.ip
        service = whitelist.service
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "ACCEPT"])
        
        whitelist.delete()
        messages.success(request, "White IP berhasil dihapus.")
        logging.info(f"Success to delete Whitelist for {ip} service {service}")
    except CalledProcessError as e:
        # Tangani kesalahan saat perintah iptables gagal
        logging.error(f"Failed to delete iptables rule for {ip}: {str(e)}")
        logging.error(f"Failed to delete Whitelist {ip} for {service}")
        messages.error(request, "White IP gagal dihapus.")
        # Anda bisa menambahkan pesan kesalahan ke context untuk ditampilkan di template
    
    
    return redirect('whitelist')
    


def enable_service():
    try:
        # Command to be executed

        command = ['sudo','systemctl', 'enable', '--now', 'idps.service']
        logging.info(f"Enabling IDPS Service")
        
        # Running the command
        result = subprocess.run(command, check=True, text=True, capture_output=True)
        
        # Print the stdout and stderr
        print("stdout:", result.stdout)
        print("stderr:", result.stderr)

    except subprocess.CalledProcessError as e:
        print(f"Error occurred: {e}")
        print("stdout:", e.stdout)
        print("stderr:", e.stderr)
def disable_service():
    try:
        # Command to be executed
        command = ['sudo', 'systemctl', 'stop', '--now', 'idps.service']
        subprocess.check_call(["sudo", "netfilter-persistent", "save"])
        logging.info(f"Disabling IDPS Service")
        # Running the command
        result = subprocess.run(command, check=True, text=True, capture_output=True)
        
        # Print the stdout and stderr
        print("stdout:", result.stdout)
        print("stderr:", result.stderr)

    except subprocess.CalledProcessError as e:
        print(f"Error occurred: {e}")
        print("stdout:", e.stdout)
        print("stderr:", e.stderr)

