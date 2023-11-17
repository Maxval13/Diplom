from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.db import models
from django.utils.translation import gettext_lazy as _
from django_rest_passwordreset.tokens import get_token_generator

STATE_CHOICES = (
    ('basket', 'Статус корзины'),
    ('new', 'Новый'),
    ('confirmed', 'Подтвержден'),
    ('assembled', 'Собран'),
    ('sent', 'Отправлен'),
    ('delivered', 'Доставлен'),
    ('canceled', 'Отменен'),
)

USER_TYPE_CHOICES = (
    ('shop', 'Магазин'),
    ('buyer', 'Покупатель'),
)


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(email, password, **extra_fields)


class User(AbstractUser):
    REQUIRED_FIELDS = []
    objects = UserManager()
    USERNAME_FIELD = "email"

    username_validator = UnicodeUsernameValidator()
    username = models.CharField(
        _("username"),
        max_length=150,
        unique=True,
        help_text=_(
            "Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only."
        ),
        validators=[username_validator],
        error_messages={
            "unique": _("A user with that username already exists."),
        },
    )
    email = models.EmailField(_("email address"), unique=True, blank=False)
    type = models.CharField(max_length=5, choices=USER_TYPE_CHOICES, default='buyer', verbose_name='Тип пользователя')
    company = models.CharField(max_length=40, blank=True, verbose_name='Компания')
    position = models.CharField(max_length=40, blank=True, verbose_name='Должность')

    class Meta:
        verbose_name = "Пользователь"
        verbose_name_plural = "Список пользователей"
        ordering = ('email',)

    def __str__(self):
        return f'{self.last_name} {self.first_name}'


class Shop(models.Model):
    name = models.CharField(max_length=40, verbose_name='Название магазина')
    url = models.URLField(null=True, blank=True, verbose_name='Ссылка')
    filename = models.FileField(null=True, blank=True, upload_to='shop/', verbose_name='Файл с данными')
    user = models.OneToOneField(User, blank=True, null=True, verbose_name='Пользователь', on_delete=models.CASCADE)
    state = models.BooleanField(default=True, verbose_name='Статус получения заказа')
    admin_email = models.EmailField(verbose_name='Email администратора магазина', null=True, blank=True)

    class Meta:
        verbose_name = 'Магазин'
        verbose_name_plural = "Список магазинов"
        ordering = ('-name',)

    def __str__(self):
        return self.name


class Category(models.Model):
    name = models.CharField(max_length=40, verbose_name='Название категории')
    shops = models.ManyToManyField(Shop, blank=True, related_name='categories', verbose_name='Магазины')

    class Meta:
        verbose_name = 'Категория'
        verbose_name_plural = "Список категорий"
        ordering = ('-name',)

    def __str__(self):
        return self.name


class Product(models.Model):
    name = models.CharField(max_length=80, verbose_name='Название продукта')
    category = models.ForeignKey(Category, blank=True, related_name='products', verbose_name='Категория',
                                 on_delete=models.CASCADE)

    class Meta:
        verbose_name = 'Продукт'
        verbose_name_plural = "Список продуктов"
        ordering = ('-name',)

    def __str__(self):
        return self.name


class ProductInfo(models.Model):
    product = models.ForeignKey(Product, blank=True, related_name='product_infos', verbose_name='Продукт',
                                on_delete=models.CASCADE)
    shop = models.ForeignKey(Shop, blank=True, related_name='shop_infos', verbose_name='Магазин',
                             on_delete=models.CASCADE)
    model = models.CharField(max_length=80, blank=True, verbose_name='Модель')
    external_id = models.PositiveIntegerField(verbose_name='Внешний идентификатор')
    quantity = models.PositiveIntegerField(verbose_name='Количество')
    price = models.PositiveIntegerField(verbose_name='Цена')
    price_rrc = models.PositiveIntegerField(verbose_name='Рекомендуемая розничная цена')

    class Meta:
        verbose_name = 'Информация о продукте'
        verbose_name_plural = "Информационный список о продуктах"
        constraints = [
            models.UniqueConstraint(fields=['product', 'shop', 'external_id'], name='unique_product_info'),
        ]
        ordering = ('-model',)


class Parameter(models.Model):
    name = models.CharField(max_length=60, verbose_name='Название параметра')

    class Meta:
        verbose_name = 'Имя параметра'
        verbose_name_plural = "Список имен параметров"
        ordering = ('-name',)

    def __str__(self):
        return self.name


class ProductParameter(models.Model):
    product_info = models.ForeignKey(ProductInfo, blank=True, related_name='product_parameters',
                                     verbose_name='Информация о продукте', on_delete=models.CASCADE)
    parameter = models.ForeignKey(Parameter, blank=True, related_name='product_parameters',
                                  verbose_name='Параметр', on_delete=models.CASCADE)
    value = models.CharField(max_length=100, verbose_name='Значение')

    class Meta:
        verbose_name = 'Параметр'
        verbose_name_plural = "Список параметров"
        constraints = [
            models.UniqueConstraint(fields=['product_info', 'parameter'], name='unique_product_parameter'),
        ]


class Contact(models.Model):
    user = models.ForeignKey(User, blank=True, related_name='contacts',
                             verbose_name='Пользователь', on_delete=models.CASCADE)
    city = models.CharField(max_length=50, verbose_name='Город')
    street = models.CharField(max_length=100, verbose_name='Улица')
    house = models.CharField(max_length=15, blank=True, verbose_name='Дом')
    structure = models.CharField(max_length=15, blank=True, verbose_name='Корпус')
    building = models.CharField(max_length=15, blank=True, verbose_name='Строение')
    apartment = models.CharField(max_length=15, blank=True, verbose_name='Квартира')
    phone = models.CharField(max_length=20, verbose_name='Телефон')

    class Meta:
        verbose_name = 'Контакты пользователя'
        verbose_name_plural = "Список контактов пользователя"

    def __str__(self):
        return f'{self.city} {self.street} {self.house}'


class Order(models.Model):
    user = models.ForeignKey(User, blank=True, related_name='orders',
                             verbose_name='Пользователь', on_delete=models.CASCADE)
    contact = models.ForeignKey(Contact, blank=True, null=True, verbose_name='Контакт',
                                on_delete=models.CASCADE)
    dt = models.DateTimeField(auto_now_add=True, verbose_name='Дата')
    state = models.CharField(max_length=15, choices=STATE_CHOICES, verbose_name='Статус')

    class Meta:
        verbose_name = 'Заказ'
        verbose_name_plural = "Список заказ"
        ordering = ('-dt',)

    def __str__(self):
        return str(self.dt)


class OrderItem(models.Model):
    order = models.ForeignKey(Order, blank=True, related_name='ordered_items',
                              verbose_name='Заказ', on_delete=models.CASCADE)
    product_info = models.ForeignKey(ProductInfo, blank=True, related_name='ordered_items',
                                     verbose_name='Информация о продукте', on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(verbose_name='Количество')

    class Meta:
        verbose_name = 'Заказанная позиция'
        verbose_name_plural = "Список заказанных позиций"
        constraints = [
            models.UniqueConstraint(fields=['order_id', 'product_info'], name='unique_order_item'),
        ]
