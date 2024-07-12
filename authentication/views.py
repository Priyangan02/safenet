from django.shortcuts import render
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.models import User
from django.views.generic import DetailView
from django.shortcuts import redirect

# Create your views here.
def user_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('home')
        else:
            messages.error(request, "Login error: username or password not found!")
    return render(request, 'login.html')
def user_logout(request):
    logout(request)
    messages.success(request,'Logout success')
    return redirect('login')

class UserDetail(DetailView):
    model = User
    context_object_name = "user"
    