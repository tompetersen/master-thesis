# -*- coding: utf-8 -*-
# Generated by Django 1.11.4 on 2018-01-10 11:40
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Applicant',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Config',
            fields=[
                ('key', models.CharField(max_length=20, primary_key=True, serialize=False)),
                ('value', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='StoreEntry',
            fields=[
                ('pseudonym', models.CharField(editable=False, max_length=256, primary_key=True, serialize=False)),
                ('content', models.TextField()),
                ('search_token', models.TextField()),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('usages', models.IntegerField(default=0)),
                ('last_access', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='StoreEntryRequest',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('applicant', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='service.Applicant')),
                ('store_entry', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='service.StoreEntry')),
            ],
        ),
        migrations.CreateModel(
            name='ThresholdClient',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('client_address', models.GenericIPAddressField()),
                ('client_port', models.IntegerField()),
                ('name', models.CharField(max_length=50, unique=True)),
            ],
        ),
    ]