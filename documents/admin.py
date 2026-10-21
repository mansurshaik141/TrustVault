
from django.contrib import admin
from .models import AuditLog, Document, DocumentAccess


@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    list_display = (
        "title",
        "owner",
        "category",
        "created_at",
    )
    search_fields = ("title", "owner__username", "category")
    list_filter = ("category", "created_at")


@admin.register(DocumentAccess)
class DocumentAccessAdmin(admin.ModelAdmin):
    list_display = (
        "document",
        "user",
        "permission",
        "granted_at",
    )
    search_fields = (
        "document__title",
        "user__username",
    )
    list_filter = ("permission",)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = (
    "timestamp",
    "user",
    "document",
    "action",
    "result",
    "details",
    "ip_address",
)
    search_fields = (
        "user__username",
        "document__title",
        "action",
        "details",
    )
    list_filter = (
        "action",
        "result",
        "timestamp",
    )
    readonly_fields = (
    "user",
    "document",
    "action",
    "result",
    "timestamp",
    "ip_address",
    "user_agent",
    "details",
    "previous_hash",
    "record_hash",
)
    date_hierarchy = "timestamp"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
