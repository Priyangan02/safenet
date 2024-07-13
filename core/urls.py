from django.urls import path
from .views import *
urlpatterns = [
    path("",IndexView.as_view(),name="home"),
    path("sshsuccess", SSHSuccessView.as_view(),name="sshsuccess"),
    path("config/", ConfigView.as_view(), name="config"),
    path('whitelist/',WhiteListView.as_view(),name='whitelist'),
    path("delete-waitlist/<int:pk>/", deleteWaitList, name="delete_waitlist"),
    path("bannedip/", BannedIpView.as_view(), name="bannedip"),
    path("delete-bannedip/<int:pk>/", deleteBannedIp, name="delete_bannedip"),
]
