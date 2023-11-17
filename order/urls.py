from django.urls import path
from django.conf import settings
from django_rest_passwordreset.views import reset_password_request_token, reset_password_confirm

from . import views

app_name = 'order'

urlpatterns = [
    path('', views.IndexView.as_view(), name='home'),
    path('partner/update', views.PartnerUpdate.as_view(), name='partner-update'),
    path('partner/state', views.PartnerState.as_view(), name='partner-state'),
    path('partner/orders', views.PartnerOrders.as_view(), name='partner-orders'),
    path('user/register', views.RegisterAccount.as_view(), name='user-register'),
    path('user/register/confirm', views.ConfirmAccount.as_view(), name='user-register-confirm'),
    path('user/details', views.AccountDetails.as_view(), name='user-details'),
    path('user/contact', views.ContactView.as_view(), name='user-contact'),
    path('user/login', views.LoginAccount.as_view(), name='user-login'),
    path('user/password_reset', reset_password_request_token, name='password-reset'),
    path('user/password_reset/confirm', reset_password_confirm, name='password-reset-confirm'),
    path('categories', views.CategoryView.as_view(), name='categories'),
    path('shops', views.ShopView.as_view(), name='shops'),
    path('products', views.ProductInfoView.as_view(), name='products'),
    path('basket', views.BasketView.as_view(), name='basket'),
    path('order', views.OrderView.as_view(), name='order'),
    path('update_order', views.OrderConfirmationView.as_view(), name='update_order'),
]
