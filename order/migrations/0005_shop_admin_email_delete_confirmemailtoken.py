# Generated by Django 4.2.7 on 2023-11-16 21:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('order', '0004_alter_productinfo_shop_alter_shop_filename'),
    ]

    operations = [
        migrations.AddField(
            model_name='shop',
            name='admin_email',
            field=models.EmailField(blank=True, max_length=254, null=True, verbose_name='Email администратора магазина'),
        ),
        migrations.DeleteModel(
            name='ConfirmEmailToken',
        ),
    ]
