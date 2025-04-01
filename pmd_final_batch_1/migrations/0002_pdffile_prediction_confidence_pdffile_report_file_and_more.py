# Generated by Django 5.1.7 on 2025-03-31 08:02

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pmd_final_batch_1', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='pdffile',
            name='prediction_confidence',
            field=models.FloatField(default=0.0),
        ),
        migrations.AddField(
            model_name='pdffile',
            name='report_file',
            field=models.FileField(blank=True, null=True, upload_to='reports/'),
        ),
        migrations.AddField(
            model_name='pdffile',
            name='user',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='pdf_files', to=settings.AUTH_USER_MODEL),
        ),
        migrations.CreateModel(
            name='AnalysisResult',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('features', models.JSONField(default=dict)),
                ('explanation', models.TextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('pdf_file', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='analysis', to='pmd_final_batch_1.pdffile')),
            ],
        ),
    ]
