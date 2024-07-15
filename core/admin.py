from django.contrib import admin
from .models import *
# Register your models here.
class BannedIpAdmin(admin.ModelAdmin):
    list_display = ('tanggal', 'waktu', 'service', 'ip', )

class IdpsLogAdmin(admin.ModelAdmin):
    list_display = ('tanggal', 'waktu','message', 'service', 'ip' )
class SSHSuccessAdmin(admin.ModelAdmin):
    list_display = ('tanggal', 'waktu','protocol', 'user_login', 'ip','port' )

admin.site.register(Config)
admin.site.register(IDPSLog, IdpsLogAdmin)
admin.site.register(BannedIP,BannedIpAdmin)
admin.site.register(SSHSuccess,SSHSuccessAdmin)