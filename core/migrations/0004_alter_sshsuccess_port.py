# Generated by Django 5.0.7 on 2024-07-12 10:16

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0003_rename_waitlist_whitelist_sshsuccess'),
    ]

    operations = [
        migrations.AlterField(
            model_name='sshsuccess',
            name='port',
            field=models.IntegerField(default=22),
        ),
    ]
