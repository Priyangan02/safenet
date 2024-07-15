from django.db import models

# Create your models here.

class IDPSLog(models.Model):
    tanggal = models.DateField(auto_now_add=True)
    waktu = models.TimeField(auto_now_add=True)
    service = models.CharField(max_length=100)
    message = models.CharField(max_length=255)
    ip = models.GenericIPAddressField()

    def __str__(self):
        return f"{self.ip} - {self.service} on {self.tanggal} at {self.waktu}"
class BannedIP(models.Model):
    
    tanggal = models.DateField(auto_now_add=True)
    waktu = models.TimeField(auto_now_add=True)
    service = models.CharField(max_length=100)
    ip = models.GenericIPAddressField()

    def __str__(self):
        return f"{self.ip} - {self.service} on {self.tanggal} at {self.waktu}"
    
class WhiteList(models.Model):
    tanggal = models.DateField(auto_now_add=True)
    waktu = models.TimeField(auto_now_add=True)
    service = models.CharField(max_length=100)
    ip = models.GenericIPAddressField()
    def __str__(self):
        return f"{self.ip} - {self.service} on {self.tanggal} at {self.waktu}"
class SSHSuccess(models.Model):
    id_idpslog = models.ForeignKey(IDPSLog, on_delete=models.CASCADE) 
    tanggal = models.DateField(auto_now_add=True)
    waktu = models.TimeField(auto_now_add=True)
    protocol = models.CharField(max_length=100)
    user_login = models.CharField(max_length=50)
    port = models.CharField(max_length=10)
    ip = models.GenericIPAddressField()
    def __str__(self):
        return f"{self.ip}{self.port} "

class Config(models.Model):
    th_ssh = models.IntegerField(default=5)
    th_flood = models.IntegerField(default=1000)
    def __str__(self):
        return f"SSH Threshold {self.th_ssh},Flood Threshold {self.th_flood} "

class ConfigStatus(models.Model):
    
    status = models.CharField(max_length=5)
    def __str__(self):
        return f"Status {self.status}"
    
