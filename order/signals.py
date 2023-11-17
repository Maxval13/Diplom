from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import EmailMultiAlternatives
from django.dispatch import receiver, Signal
from django_rest_passwordreset.signals import reset_password_token_created
from django.core.mail import send_mail
from rest_framework.authtoken.models import Token

from .models import User

new_user_registered = Signal()
new_updated_order = Signal()
new_order = Signal()


@receiver(reset_password_token_created)
def password_reset_token_created(sender, instance, reset_password_token, **kwargs):
    """
    Отправляем письмо с токеном для сброса пароля
    When a token is created, an e-mail needs to be sent to the user
    :param sender: View Class that sent the signal
    :param instance: View Instance that sent the signal
    :param reset_password_token: Token Model Object
    :param kwargs:
    :return:
    """
    # send an e-mail to the user

    msg = EmailMultiAlternatives(
        # title:
        f"Password Reset Token for {reset_password_token.user}",
        # message:
        reset_password_token.key,
        # from:
        settings.EMAIL_HOST_USER,
        # to:
        [reset_password_token.user.email]
    )
    msg.send()


@receiver(new_user_registered)
def new_user_registered_signal(sender, user_id, **kwargs):
    """
    отправляем письмо с подтрердждением почты
    """
    # send an e-mail to the user
    user = get_user_model().objects.get(pk=user_id)
    token = Token.objects.create(user=user)
    token.save()

    msg = EmailMultiAlternatives(
        # title:
        f"Токен для пользователя {user.email}",
        # message:
        f'Токен для дальнейшей авторизации: {token.key}',
        # from:
        settings.EMAIL_HOST_USER,
        # to:
        [user.email]
    )
    msg.send()


@receiver(new_order)
def new_order_signal(sender, user_id, user_email, admin_emails, **kwargs):
    """
    отправяем письмо при изменении статуса заказа
    """
    # send an e-mail to the user
    user_email = user_email

    send_mail(
        f'Подтверждение заказа',
        'Ваш заказ был успешно размещен.',
        settings.EMAIL_HOST_USER,
        [user_email],
        fail_silently=False,
    )

    send_mail(
        f'Заказ от пользователя {user_mail}',
        'У вас есть новый заказ для исполнения.',
        settings.EMAIL_HOST_USER,
        admin_emails,
        fail_silently=False,
    )


@receiver(new_updated_order)
def new_updated_order_signal(sender, user_email, admin_emails, **kwargs):
    """
    Отправка письма при изменения статуса заказа
    """
    user_email = user_email

    send_mail(
        f'Обновление статуса заказа',
        'Статус вашего заказа был обновлен.',
        settings.EMAIL_HOST_USER,
        [user_email],
        fail_silently=False,
    )

    send_mail(
        f'Изменение заказа от пользователя {user_email}',
        'У вас есть измененый заказ для исполнения.',
        settings.EMAIL_HOST_USER,
        admin_emails,
        fail_silently=False,
    )
