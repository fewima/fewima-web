from django.urls import include, path
urlpatterns = [path("", include("core.urls"))]
handler400 = "core.views.error_400"
handler403 = "core.views.error_403"
handler404 = "core.views.error_404"
handler500 = "core.views.error_500"