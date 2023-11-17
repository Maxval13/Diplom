# Проект "Онлайн сервиса"

Проект представляет собой API сервис по заказу товаров для розничных сетей.
Ознакомиться с текстом задания можно по ссылке: https://github.com/netology-code/python-final-diplom

### Настройка отправки писем на email

Для отправки сообщений о создании/изменения заказа на email администратора и пользователя, выполнить следующее:

1. Создать приложение в почтовом ящике с которого будет идти рассылка.
2. Сохранить пароль доступа, полученный при создании приложения в переменной "EMAIL_HOST_PASSWORD" в файле ".env"
3. Отредактируйте файл ".env" в нем указать все необходимые значения в переменных.

### Обновление прайса от поставщика через YAML-файл

Для загрузки нового прайса от поставщика выполните следубщие шаги:

1. Отправить POST-запрос на соответсвующий эндпоинт, передав файл в параметрах запроса под ключом "file"
2. Принимайте и обрабатывайте загруженный файл в соответствующий представлении.

Пример запроса:

```http request
POST http://127.0.0.1:8000/partner/update 
Request Headers
Host: example.com
Content-Type: multipart/form-data
Authorization : «authtoken»

Body
form-data
Content-Disposition: form-data; name="file"; filename="shop1.yaml"
Content-Type: application/x-yaml
file:  shop1.yaml
```

Другие примеры запросов находятся в файле: "http_request_example.txt".







