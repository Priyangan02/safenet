from django.shortcuts import render, redirect
from .models import *
from django.views.generic import ListView,TemplateView

class IndexView(ListView):
    model = IDPSLog
    context_object_name ='idpslog'
    template_name = "index.html"
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["title"] = "Home"
        return context

class ConfigView(TemplateView):
    template_name = "config.html"
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["title"] = "Home"
        return context

class BannedIpView(ListView):
    template_name="bannedip.html"
    model = BannedIP
    context_object_name = "bannedip"
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["title"] = "Banned Ip"
        return context
    
    def post(self, request, *args, **kwargs):
        # Ambil data POST yang dikirimkan oleh pengguna
        ip = request.POST.get('ip', '')
        service = request.POST.get('service', '')
        # Lakukan sesuatu dengan data POST yang diterima, misalnya simpan ke database
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
    

class WaitListView(ListView):
    template_name = "waitlist.html"
    model = WaitList
    context_object_name = "waitlist"
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["title"] = "waitlist"
        return context
    def post(self, request, *args, **kwargs):
        # Ambil data POST yang dikirimkan oleh pengguna
        ip = request.POST.get('ip', '')
        service = request.POST.get('service', '')
        

        # Lakukan sesuatu dengan data POST yang diterima, misalnya simpan ke database
        WaitList.objects.create(service=service, ip=ip)

        # Ambil ulang data yang akan ditampilkan dalam ListView setelah penambahan
        queryset = self.get_queryset()
        context = self.get_context_data(object_list=queryset)
        return render(request, self.template_name, context)
    

def deleteWaitList(request,pk):
    bannedip = WaitList.objects.get(pk=pk)    
    bannedip.delete()
    return redirect('waitlist')
    
