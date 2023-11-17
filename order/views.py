from distutils.util import strtobool

from django_filters.rest_framework import DjangoFilterBackend
import yaml
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from rest_framework.pagination import PageNumberPagination
from rest_framework.parsers import MultiPartParser
from django_filters import rest_framework as filters
from rest_framework.filters import OrderingFilter
from django.core.validators import URLValidator
from django.db import IntegrityError
from django.db.models import Q, Sum, F
from django.http import JsonResponse
from django.db import transaction
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from ujson import loads as load_json
from yaml import load as load_yaml
from rest_framework import status

from .filters import CategoryFilter, ProductFilter, ShopFilter, OrderFilter
from .models import (Shop, Category, Product, ProductInfo, Parameter, ProductParameter, Order, OrderItem,
                     Contact, USER_TYPE_CHOICES)
from .serializers import (UserSerializer, CategorySerializer, ShopSerializer, ProductInfoSerializer,
                          OrderItemSerializer, OrderSerializer, ContactSerializer)
from .signals import new_user_registered, new_order, new_updated_order


def base_url(request):
    url = request.build_absolute_uri('/')
    return url

class CustomPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100

class IndexView(APIView):
    """
    Отображает доступные действия
    """

    @staticmethod
    def get(request):
        register_url = f'{base_url(request)}user/register'
        login_url = f'{base_url(request)}user/login'
        category_url = f'{base_url(request)}categories'
        shop_url = f'{base_url(request)}shops'
        product_url = f'{base_url(request)}products'
        if Response.status_code == status.HTTP_200_OK:
            return Response(
                {'message': 'Добро пожаловать! Вы можете зарегистрироваться.',
                 'register_url': register_url,
                 'message_2': 'Если вы уже зарегистрированы, то Вы можете авторизоваться.',
                 'login_url': login_url,
                 'message_3': 'Вы можете просмотреть список доступных категорий товаров.',
                 'category_url': category_url,
                 'message_4': 'Вы можете просмотреть список доступных магазинов.',
                 'shop_url': shop_url,
                 'message_5': 'Вы можете просмотреть список доступных товаров.',
                 'product_url': product_url}
            )


class RegisterAccount(APIView):
    """
    Для регистрации покупателей
    """

    def post(self, request, *args, **kwargs):

        # проверяем обязательные аргументы
        if {'first_name', 'last_name', 'email', 'password', 'company', 'position'}.issubset(request.data):
            errors = {}
            # проверяем пароль на сложность
            try:
                validate_password(request.data['password'])
            except ValidationError as password_error:
                error_array = []
                for item in password_error:
                    error_array.append(item)
                return JsonResponse({'Status': False, 'Errors': {'password': error_array}}, status=400)
            else:
                user_serializer = UserSerializer(data=request.data)
                if user_serializer.is_valid():
                    user = user_serializer.save()
                    user.set_password(request.data['password'])
                    user.save()
                    new_user_registered.send(sender=self.__class__, user_id=user.id)
                    login_url = f'{base_url(request)}user/login'
                    return JsonResponse({'Status': True,
                                     'message': 'Вы успешно зарегистрированы. Теперь вы можете авторизоваться.',
                                     'login_url': login_url}, status=201
                                    )
                else:
                    return JsonResponse({'Status': False, 'Errors': user_serializer.errors}, status=400)

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'}, status=400)


class ConfirmAccount(APIView):
    """
    Класс для подтверждения почтового адреса
    """

    # Регистрация методом POST
    def post(self, request, *args, **kwargs):

        # проверяем обязательные аргументы
        if {'email', 'token'}.issubset(request.data):

            token = ConfirmEmailToken.objects.filter(user__email=request.data['email'],
                                                     key=request.data['token']).first()
            if token:
                token.user.is_active = True
                token.user.save()
                token.delete()
                return JsonResponse({'Status': True})
            else:
                return JsonResponse({'Status': False, 'Errors': 'Неправильно указан токен или email'})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


class AccountDetails(APIView):
    """
    Класс для работы данными пользователя
    """
    authentication_classes = [TokenAuthentication]

    # получить данные
    @staticmethod
    def get(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    # Редактирование методом POST
    @staticmethod
    def put(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)
        # проверяем обязательные аргументы
        user = request.user
        if 'password' in request.data:
            errors = {}
            # проверяем пароль на сложность
            try:
                validate_password(request.data['password'])
            except ValidationError as password_error:
                # # noinspection PyTypeChecker
                # for item in password_error:
                #     error_array.append(item)
                return JsonResponse({'Status': False, 'Errors': {'password': password_error.messages}}, status=400)
            else:
                user.set_password(request.data['password'])

        # проверяем остальные данные
        user_serializer = UserSerializer(user, data=request.data, partial=True)
        if user_serializer.is_valid():
            user_serializer.save()

            if 'type' in request.data:
                new_type = request.data['type']
                user.type = new_type
                user.save()
            return JsonResponse({'Status': True})
        else:
            return JsonResponse({'Status': False, 'Errors': user_serializer.errors}, status=400)

    @staticmethod
    def delete(request):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Errors': 'Log in required'}, status=403)

        user = request.user
        try:
            user.auth_token.delete()
            user.delete()
            return JsonResponse({'Status': True, 'Messages': 'Пользователь успешно удален'}, status=200)
        except Exception as ex:
            return  JsonResponse({'Status': False, 'Errors': str(ex)}, status=400)


class LoginAccount(APIView):
    """
    Класс для авторизации пользователей
    """
    authentication_classes = [TokenAuthentication]

    @staticmethod
    def post(request, *args, **kwargs):

        if {'email', 'password'}.issubset(request.data.keys()):
            user = authenticate(request, username=request.data['email'], password=request.data['password'])

            if user is not None and user.is_active:
                order_url = f'{base_url(request)}order'
                # token, _ = Token.objects.get_or_create(user=user)
                return JsonResponse({'Status': True, 'order_url': order_url,
                                     'message': 'Вы успешно авторизованы. Теперь можете делать заказ.'}, status=200)
                # return JsonResponse({'Status': True, 'Token': token.key})
            else:
               return JsonResponse({'Status': False, 'Errors': 'Неверный email или пароль'}, status=401)
        else:
            return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'}, status=400)


class CategoryView(ListAPIView):
    """
    Класс для просмотра категорий
    """
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = CategoryFilter
    pagination_class = CustomPagination


class ShopView(ListAPIView):
    """
    Класс для просмотра списка магазинов
    """
    serializer_class = ShopSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = ShopFilter
    queryset = Shop.objects.filter(state=True)
    pagination_class = CustomPagination


class ProductInfoView(APIView):
    """
    Класс для поиска товаров
    """

    def get(self, request, *args, **kwargs):

        query = Q(shop__state=True)
        shop_id = request.query_params.get('shop_id')
        category_id = request.query_params.get('category_id')

        if shop_id:
            query = query & Q(shop_id=shop_id)

        if category_id:
            query = query & Q(product__category_id=category_id)

        # фильтруем и отбрасываем дуликаты
        queryset = ProductInfo.objects.filter(
            query).select_related(
            'shop', 'product__category').prefetch_related(
            'product_parameters__parameter').distinct()

        serializer = ProductInfoSerializer(queryset, many=True)

        return Response(serializer.data)


class BasketView(APIView):
    """
    Класс для работы с корзиной пользователя
    """
    authentication_classes = [TokenAuthentication]

    # получить корзину

    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)
        basket = Order.objects.filter(
            user_id=request.user.id, state='basket').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()

        serializer = OrderSerializer(basket, many=True)
        return Response(serializer.data)

    # редактировать корзину
    @staticmethod
    def post(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        items_dict = request.data.get('items')
        if not items_dict:
            return JsonResponse({'Status': False, 'Errors': 'Указаны не все необходимые аргументы'}, status=400)

        auth_heder = request.META.get('HTTP_AUTHORIZATION')
        auth_token = auth_heder.split()[1]
        user_id = Token.objects.get(key=auth_token).user_id
        contact_id = Contact.objects.get(user_id=user_id).id
        basket, created = Order.objects.get_or_create(user_id=user_id, contact_id=contact_id,
                                                              state='basket')
        objects_created = 0
        for order_item in items_dict:
            product_name = order_item.get('name')
            quantity = order_item.get('quantity')

            if product_name and quantity:
                product = Product.objects.get(name=product_name).id
                product_id = ProductInfo.objects.get(product_id=product).id

                order_item_data = {
                            'order': basket.id,
                            'product_info': product_id,
                            'quantity': quantity
                        }

                serializer = OrderItemSerializer(data=order_item_data)
                if serializer.is_valid():
                    try:
                        serializer.save()
                    except IntegrityError as error:
                        return JsonResponse({'Status': False, 'Errors': str(error)}, status=400)
                    else:
                        objects_created += 1
                else:
                    return JsonResponse({'Status': False, 'Errors': serializer.errors}, status=400)
            else:
                return JsonResponse({'Status': False, 'Errors': 'Указаны не все необходимые аргументы'})

        return JsonResponse({'Status': True, 'Создано объектов': objects_created})



    # удалить товары из корзины
    @staticmethod
    def delete(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        data = request.data
        order_id = data.get('order_id')
        items_list = data.get('items')
        if not order_id or not items_list:
            return JsonResponse({'Status': False, 'Errors': 'Для удаления укажите необходимые аргументы'})

        objects_deleted = False
        items_order_delete = OrderItem.objects.filter(order_id=order_id)
        for product_name in items_list:
            try:
                product = Product.objects.get(name=product_name).id
                product_info = ProductInfo.objects.get(product_id=product).id
                count_delete = items_order_delete.filter(product_info_id=product_info).delete()[0]
                objects_deleted += count_delete
            except ObjectDoesNotExist:
                return JsonResponse({'Status': False, 'Errors': f'Не найдены товары "{product_name}" для удаления'},
                                    status=400)
        if objects_deleted:
            # count_deleted = OrderItem.objects.filter(query).delete()[0]
            return JsonResponse({'Status': True, 'Удалено объектов': objects_deleted})

        return JsonResponse({'Status': False, 'Errors': 'Не найдены товары для удаления'}, status=400)

    # добавить позиции в корзину
    @staticmethod
    def put(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        items_dict = request.data.get('items')
        if not items_dict:
            return JsonResponse({'Status': False, 'Errors': 'Указаны не все необходимые аргументы'}, status=400)

        auth_heder = request.META.get('HTTP_AUTHORIZATION')
        auth_token = auth_heder.split()[1]
        user_id = Token.objects.get(key=auth_token).user_id
        contact_id = Contact.objects.get(user_id=user_id).id
        basket, created = Order.objects.get_or_create(user_id=user_id, contact_id=contact_id,
                                                              state='basket')
        objects_updated = 0
        for order_item in items_dict:
            if 'name' in order_item and 'quantity' in order_item:
                product_name = order_item['name']
                new_quantity = order_item['quantity']
                try:
                    product = Product.objects.get(name=product_name).id
                    product_id = ProductInfo.objects.get(product_id=product).id
                    item_order_obj, created = OrderItem.objects.update_or_create(order=basket,
                                                                                 product_info_id=product_id,
                                                                                 defaults={'quantity': new_quantity}
                                                                                 )
                    item_order_obj.save()
                    objects_updated += 1
                except ObjectDoesNotExist:
                    return JsonResponse({'Status': False, 'Errors': 'Нет заказа с такими данными'})
        return JsonResponse({'Status': True, 'Обновлено объектов': objects_updated})


class PartnerUpdate(APIView):
    """
    Класс для обновления прайса от поставщика
    """
    parser_classes = [MultiPartParser]
    authentication_classes = [TokenAuthentication]

    @staticmethod
    def post(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'Только для магазинов'}, status=403)

        yaml_file = request.FILES.get('file')
        if not yaml_file:
            return JsonResponse({'Status': False, 'Errors': 'Не указан файл'}, status=400)

        try:
            with transaction.atomic():
                data = yaml.safe_load(yaml_file.read())

                shop, created = Shop.objects.get_or_create(name=data['shop'], user_id=request.user.id)

                Category.objects.filter(shops=shop).delete()
                for category in data['categories']:
                    category_object, created = Category.objects.get_or_create(id=category['id'], name=category['name'])
                    category_object.shops.add(shop.id)

                ProductInfo.objects.filter(shop=shop).delete()
                for item in data['goods']:
                    product, created = Product.objects.get_or_create(name=item['name'], category_id=item['category'])
                    product_info = ProductInfo.objects.create(product=product,
                                                              external_id=item['id'],
                                                              model=item['model'],
                                                              price=item['price'],
                                                              price_rrc=item['price_rrc'],
                                                              quantity=item['quantity'],
                                                              shop=shop)
                    for name, value in item['parameters'].items():
                        parameter_object, created = Parameter.objects.get_or_create(name=name)
                        ProductParameter.objects.create(product_info=product_info,
                                                        parameter=parameter_object,
                                                        value=value)

        except Exception as ex:
            return JsonResponse({'Status': False, 'Errors': str(ex)}, status=500)

        return JsonResponse({'Status': True})


class PartnerState(APIView):
    """
    Класс для работы со статусом поставщика
    """
    authentication_classes = [TokenAuthentication]

    # получить текущий статус
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'Только для магазинов'}, status=403)

        shop = request.user.shop
        serializer = ShopSerializer(shop)
        return Response(serializer.data)

    # изменить текущий статус
    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'Только для магазинов'}, status=403)
        state = request.data.get('state')
        if state:
            try:
                Shop.objects.filter(user_id=request.user.id).update(state=strtobool(state))
                return JsonResponse({'Status': True})
            except ValueError as error:
                return JsonResponse({'Status': False, 'Errors': str(error)}, status=403)

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'}, status=400)


class PartnerOrders(APIView):
    """
    Класс для получения заказов поставщиками
    """

    authentication_classes = [TokenAuthentication]

    @staticmethod
    def get(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'Только для магазинов'}, status=403)

        order = Order.objects.filter(
            ordered_items__product_info__shop__user=request.user, state__exact='basket').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter').select_related('contact').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()

        serializer = OrderSerializer(order, many=True)
        return Response(serializer.data)


class ContactView(APIView):
    """
    Класс для работы с контактами покупателей
    """
    authentication_classes = [TokenAuthentication]

    # получить мои контакты
    @staticmethod
    def get(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)
        contact = Contact.objects.filter(user_id=request.user.id)
        serializer = ContactSerializer(contact, many=True)
        return Response(serializer.data)

    # добавить новый контакт
    @staticmethod
    def post(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if {'city', 'street', 'phone'}.issubset(request.data):
            data = request.data.copy()
            try:
                token = request.META.get('HTTP_AUTHORIZATION', '').split()[1]
                token_obj =Token.objects.get(key=token)
                user_id = token_obj.user_id
            except Token.DoesNotExist:
                return JsonResponse({'Status': False, 'Error': 'Invalid token'}, status=400)
            data['user'] = user_id
            serializer = ContactSerializer(data=data)

            if serializer.is_valid():
                serializer.save()
                return JsonResponse({'Status': True})
            else:
                return JsonResponse({'Status': False, 'Errors': serializer.errors}, status=400)
        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'}, status=400)

    # удалить контакт
    @staticmethod
    def delete(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        items_list = request.data.get('items')
        if items_list:

            query = Q()
            objects_deleted = False
            for contact_id in items_list:
                if isinstance(contact_id, int):
                    query = query | Q(user_id=request.user.id, id=contact_id)
                    objects_deleted = True

            if objects_deleted:
                deleted_count = Contact.objects.filter(query).delete()[0]
                return JsonResponse({'Status': True, 'Удалено объектов': deleted_count})
        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'}, status=400)

    # редактировать контакт
    @staticmethod
    def put(request):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if 'id' in request.data:
            if isinstance(request.data['id'], int):
                contact = Contact.objects.filter(id=request.data['id'], user_id=request.user.id).first()

                if contact:
                    serializer = ContactSerializer(contact, data=request.data, partial=True)
                    if serializer.is_valid():
                        serializer.save()
                        return JsonResponse({'Status': True})
                    else:
                        return JsonResponse({'Status': False, 'Errors': serializer.errors},
                                        status=400)

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'}, status=400)


class OrderView(APIView):
    """
    Класс для получения и размешения заказов пользователями
    """
    serializer_class = OrderSerializer
    ordering_fields = ['total_sum']
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    authentication_classes = [TokenAuthentication]

    def get_query(self):
        return Order.objects.filter(
            user_id=self.request.user.id).exclude(state='basket').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter').select_related('contact').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()

    # получить мои заказы
    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            queryset = self.get_query()
            serializer = OrderSerializer(queryset, many=True)
            return Response(serializer.data)
        else:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

    # разместить заказ из корзины
    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if {'contact', 'items'}.issubset(request.data):
            with transaction.atomic():
                try:
                    contact_list = request.data.get('contact', [])

                    for contact_data in contact_list:
                        contact_phone = contact_data['phone']
                        contact_city = contact_data['city']
                        contact_street = contact_data['street']
                        contact_house = contact_data['house']
                        contact_apartment = contact_data['apartment']
                        user_id = request.user.id
                        contact, created = Contact.objects.get_or_create(user_id=user_id,
                                                                         phone=contact_phone,
                                                                         city=contact_city,
                                                                         street=contact_street,
                                                                         house=contact_house,
                                                                         apartment=contact_apartment)
                        user_email = request.user.email
                        order = Order.objects.create(user=request.user, contact_id=contact.id, state='new')
                        items = request.data['items']
                        for item in items:
                            product_name = item['name']
                            product_quantity = item['quantity']
                            product = Product.objects.get(name=product_name)
                            product_info = ProductInfo.objects.get(product=product)
                            product_id = Product.objects.get(name=product_name).id

                            OrderItem.objects.create(order=order, product_info=product_info, quantity=product_quantity)
                            shop =ProductInfo.objects.get(product_id=product_id).shop_id
                            shop1 = Shop.objects.get(id=shop)
                            admin_email = shop1.admin_email
                            if admin_email:
                                new_order.send(sender=self.__class__, user_id=request.user.id, user_email=user_email,
                                               admin_emails=[admin_email])

                        order_url = f'{base_url(request)}order'
                        order_id = order.id
                        response_data = {
                            'Status': True,
                            'Message': f'Спасибо за заказ! Номер вашего заказа: {order_id}.'
                                       f'Наш оператор свяжется с вами в ближайшее время для уточнения деталей заказа.',
                            'OrderDetails': f'Статус заказов вы можете посмотреть в разделе "Заказы" по сслыке: '
                                            f'{order_url}'
                        }
                        return Response(response_data)
                except ObjectDoesNotExist:
                    return JsonResponse({'Status': False, 'Errors': 'Ошибка при создании заказа'})
                except Exception as ex:
                    return JsonResponse({'Status': False, 'Errors': str(ex)})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})

    @staticmethod
    def delete(request):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        items_list = request.data.get('items')
        if items_list:
            query = Q()
            objects_deleted = False
            for order_id in items_list:
                if isinstance(order_id, int):
                    query = query | Q(user_id=request.user.id, id=order_id)
                    objects_deleted = True

            if objects_deleted:
                count_deleted = Order.objects.filter(query).delete()[0]
                OrderItem.objects.filter(order_id__in=items_list).delete()
                return JsonResponse({'Status': True, 'Заказ удалён. Удалено объектов': count_deleted})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'}, status=400)



class OrderConfirmationView(APIView):
    """
    Класс для подтверждения, обновления и отображения деталей заказа
    """
    authentication_classes = [TokenAuthentication]

    def get_queryset(self):
        return Order.objects.filter(user=self.request.user).exclude(state='basket').select_related('contact').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()

    def get(self, request):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)
        orders = Order.objects.filter(user=self.request.user).exclude(state='basket').select_related('contact')
        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)

    def put(self, request):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if {'id', 'contact', 'items'}.issubset(request.data):
            if isinstance(request.data['id'], int):
                try:
                    order = Order.objects.get(user=request.user, id=request.data['id'])
                    contact_phone = request.data['contact']
                    contact = Contact.objects.get(phone=contact_phone).id
                    order.contact_id = contact
                    order.state = 'new'
                    order.save()
                    items = request.data['items']
                    for item in items:
                        product_name = item['name']
                        product_quantity = item['quantity']
                        product = Product.objects.get(name=product_name).id
                        product_id = ProductInfo.objects.get(product_id=product).id

                        try:
                            order_item = OrderItem.objects.get(order=order, product_info_id=product_id)
                            order_item.quantity = product_quantity
                            order_item.save()
                        except ObjectDoesNotExist:
                            OrderItem.objects.create(order=order, product_info_id=product_id, quantity=product_quantity)
                        user_email = request.user.email
                        shop = ProductInfo.objects.get(product_id=product_id).shop_id
                        shop1 = Shop.objects.get(id=shop)
                        admin_email = shop1.admin_email
                        if admin_email:
                            new_updated_order.send(sender=self.__class__, user_id=request.user.id, user_email=user_email,
                                               admin_emails=[admin_email])
                        else:
                            order_url = f'{base_url(request)}order'
                            response_data = {
                                'Status': True,
                                'Message': f'Ваш заказ был изменён.',
                                'OrderDetails': f'Статус заказов вы можете посмотреть в разделе "Заказы" по ссылке: {order_url}'
                            }
                            return Response(response_data)

                except ObjectDoesNotExist:
                    return JsonResponse({'Status': False, 'Errors': 'Заказ не найден'})
                except Exception as ex:
                    return JsonResponse({'Status': False, 'Errors': str(ex)})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})
