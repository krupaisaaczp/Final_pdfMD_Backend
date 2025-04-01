# backend/urls.py
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    # Change this to include the 'api/' prefix here instead
    path('api/', include()),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    # Include your app's URLs without prefix - it will handle the 'api/' part
    path('', include(''pmd_final_batch_1.urls'')),
    # Add any other URL includes here
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)