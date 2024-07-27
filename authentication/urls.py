from django.urls import path
from . import views
urlpatterns = [
    path("login/", views.user_login, name="login"),
    path("logout/", views.user_logout, name="logout"),
    path('user/', views.UserDetailView.as_view(), name='user_detail'),
]
