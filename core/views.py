from django.shortcuts import render, redirect
from .models import *
from django.views.generic import ListView,TemplateView
import json
import logging
from subprocess import CalledProcessError
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
class IndexView(ListView):
    model = IDPSLog
    context_object_name ='idpslog'
    ordering = ['-tanggal','-waktu']
    template_name = "index.html"
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["title"] = "Home"
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
class ConfigView(TemplateView):
    template_name = "config.html"
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["title"] = "Config"
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
            subprocess.check_call(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        except CalledProcessError as e:
            # Tangani kesalahan saat perintah iptables gagal
            logging.error(f"Failed to delete iptables rule for {ip}: {str(e)}")
            # Anda bisa menambahkan pesan kesalahan ke context untuk ditampilkan di template
        BannedIP.objects.create(service=service, ip=ip)

        # Ambil ulang data yang akan ditampilkan dalam ListView setelah penambahan
        queryset = self.get_queryset()
        context = self.get_context_data(object_list=queryset)
        return render(request, self.template_name, context)


def deleteBannedIp(request,pk):
    bannedip = BannedIP.objects.get(pk=pk)
    BannedIP.objects.get(pk=pk)
    bannedip.delete()
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
            subprocess.check_call(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
        except CalledProcessError as e:
            # Tangani kesalahan saat perintah iptables gagal
            logging.error(f"Failed to delete iptables rule for {ip}: {str(e)}")
            # Anda bisa menambahkan pesan kesalahan ke context untuk ditampilkan di template
        # Lakukan sesuatu dengan data POST yang diterima, misalnya simpan ke database
        WhiteList.objects.create(service=service, ip=ip)

        # Ambil ulang data yang akan ditampilkan dalam ListView setelah penambahan
        queryset = self.get_queryset()
        context = self.get_context_data(object_list=queryset)
        return render(request, self.template_name, context)
    

def deleteWaitList(request,pk):
    bannedip = WhiteList.objects.get(pk=pk)    
    bannedip.delete()
    return redirect('whitelist')
    
import subprocess

def enable_service():
    try:
        # Command to be executed
        command = ['sudo', 'systemctl', 'enable', '--now', 'idps.service']
        
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
        
        # Running the command
        result = subprocess.run(command, check=True, text=True, capture_output=True)
        
        # Print the stdout and stderr
        print("stdout:", result.stdout)
        print("stderr:", result.stderr)

    except subprocess.CalledProcessError as e:
        print(f"Error occurred: {e}")
        print("stdout:", e.stdout)
        print("stderr:", e.stderr)