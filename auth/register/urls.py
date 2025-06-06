from django.urls import path

from . import views

urlpatterns = [
    path("home", views.home, name="home"),
    path("login", views.login, name="login"),
    path("signup", views.signup, name="signup"),
    path("forgot", views.forgot, name="forgot"),
    path("confirm/", views.confirm, name="confirm"),
    path("change/", views.change, name="change")
]
