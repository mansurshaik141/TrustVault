
from django.urls import path
from . import views

app_name = "documents"

urlpatterns = [
    path("", views.document_list, name="list"),
    path("upload/", views.document_upload, name="upload"),
    path("<int:document_id>/", views.document_detail, name="detail"),
    path(
        "<int:document_id>/download/",
        views.document_download,
        name="download",
    ),
    path(
        "<int:document_id>/edit/",
        views.document_edit_check,
        name="edit",
    ),
    path(
        "<int:document_id>/share/",
        views.document_share,
        name="share",
    ),
    path(
        "<int:document_id>/revoke/<int:user_id>/",
        views.document_revoke,
        name="revoke",
    ),
]
