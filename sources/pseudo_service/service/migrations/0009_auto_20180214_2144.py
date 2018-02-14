# -*- coding: utf-8 -*-
# Generated by Django 1.11.4 on 2018-02-14 20:44
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('service', '0008_auto_20180214_2114'),
    ]

    operations = [
        migrations.AlterField(
            model_name='thresholdclient',
            name='client_address',
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='thresholdclient',
            name='client_port',
            field=models.IntegerField(blank=True, null=True),
        ),
    ]
