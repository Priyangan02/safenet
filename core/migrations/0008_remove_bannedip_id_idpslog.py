# Generated by Django 5.0.7 on 2024-07-15 06:27

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0007_bannedip_id_idpslog'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='bannedip',
            name='id_idpslog',
        ),
    ]
