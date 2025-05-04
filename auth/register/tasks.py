from celery import shared_task
from django.core.mail import EmailMultiAlternatives

@shared_task
def send(mail_subject, message, email):
    email_msg = EmailMultiAlternatives(mail_subject, message, to=[email])
    email_msg.attach_alternative(message, "text/html")
    email_msg.send()
