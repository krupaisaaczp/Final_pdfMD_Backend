from django.urls import path, include
from django.http import HttpResponse

urlpatterns = [
    path('', lambda request: HttpResponse('OK'), name='health'),
    path('api/', include('pmd_final_batch_1.urls')),
]