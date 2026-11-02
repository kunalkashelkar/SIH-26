from django.urls import path
from rest_framework.routers import DefaultRouter

urlpatterns = [
    path('api/django/products/', list_products, name='product-list'),
    path('api/django/products/<int:id>/', product_detail, name='product-detail'),
]
