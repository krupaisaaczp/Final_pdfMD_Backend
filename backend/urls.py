from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('pmd_final_batch_1.urls')),  # All app URLs under /api/
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)