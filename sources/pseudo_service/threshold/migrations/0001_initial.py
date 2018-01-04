# -*- coding: utf-8 -*-
# Generated by Django 1.11.4 on 2018-01-04 12:52
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='ThresholdClient',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('client_ip', models.GenericIPAddressField()),
                ('client_port', models.IntegerField()),
                ('name', models.CharField(max_length=50)),
            ],
        ),
    ]