# Generated by Django 5.0.7 on 2024-07-15 06:15

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0006_configstatus'),
    ]

    operations = [
        migrations.AddField(
            model_name='bannedip',
            name='id_idpslog',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='core.idpslog'),
            preserve_default=False,
        ),
    ]
