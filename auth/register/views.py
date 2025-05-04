from django.shortcuts import render
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.tokens import PasswordResetTokenGenerator 
from django.shortcuts import redirect, render
from django.contrib.auth import authenticate
from django.contrib import auth
from django.http import HttpResponse
from django import forms
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import EmailMultiAlternatives
import six
from .tasks import send

data = {}

class AccountActivationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            six.text_type(user.pk) + six.text_type(timestamp) +
            six.text_type(user.email)
        )
account_activation_token = AccountActivationTokenGenerator()


def home(request):
    if request.user.is_authenticated:
        return HttpResponse("Hello, world. You're logged in.")
    else:
        return HttpResponse("Log in first")


def login(request):
    if request.method == "GET":
        return render(request, "login.html")
    elif request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(username=username, password=password)
        if user is not None:
            auth.login(request, user)
            return redirect("/home")
        else:
            return HttpResponse("Nope..")
    else:
        return HttpResponse("wrong request method")

def signup(request):
    if request.method == "GET":
        return render(request, "register.html")
    elif request.method == 'POST':
        email = request.POST.get('email')
        username = request.POST.get('username')
        if not User.objects.filter(email=email).exists() \
          and not User.objects.filter(username=username).exists():
            user = User.objects.create_user(username=username,
                                            email=email,
                                            password=request.POST.get('password'))
            user.is_active = False
            user.save()
            current_site = get_current_site(request)
            mail_subject = 'Activate your blog account.'
            message = render_to_string('acc_active_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token':account_activation_token.make_token(user),
            })
            send.delay(mail_subject, message, email)
            return HttpResponse('Please confirm your email address to complete the registration')
        else:
            return HttpResponse('Account with such cridentials already exists')
    else:
        return HttpResponse("wrong request method")

def forgot(request):
    if request.method == "GET": 
        return render(request, "forgot.html")
    elif request.method == "POST": 
        email = request.POST.get('email')
        password = request.POST.get('password')
        data[email] = password
        if User.objects.filter(email=email).exists(): 
            user = User.objects.filter(email=email)[0]
            current_site = get_current_site(request) 
            mail_subject = 'Reset password'
            message = render_to_string('change_password.html', {
                'user': user, 
                'domain': current_site.domain, 
                'uid': urlsafe_base64_encode(force_bytes(user.pk)), 
                'token':account_activation_token.make_token(user),
                })
            send.delay(mail_subject, message, email)
            return HttpResponse('Please confirm change of password')
        else: 
            return HttpResponse('Such user is not found')
    else: 
        return HttpResponse('Something went wrong') 

def change(request): 
    try:
        uidb64 = request.GET.get("uidb64")
        token = request.GET.get("token")
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        user.set_password(data[user.email])
        user.save() 
        return HttpResponse('Your password is changed')
    else:
        return HttpResponse('Your token is not valid, repeat the response')

def confirm(request):
    try:
        uidb64 = request.GET.get("uidb64")
        token = request.GET.get("token")
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        auth.login(request, user)
        return HttpResponse('Thank you for your email confirmation. You are now logged in.')
    else:
        return HttpResponse('Your token is not valid, repeat the response')

