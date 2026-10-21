from .models import DocumentAccess


def can_view_document(user, document):
    """Return True if the user may view this document."""
    if not user.is_authenticated:
        return False

    if user.is_superuser:
        return True

    if document.owner_id == user.id:
        return True

    return DocumentAccess.objects.filter(
        document=document,
        user=user,
        permission__in=[
            DocumentAccess.Permission.VIEW,
            DocumentAccess.Permission.EDIT,
        ],
    ).exists()


def can_edit_document(user, document):
    """Return True if the user may edit this document."""
    if not user.is_authenticated:
        return False

    if user.is_superuser:
        return True

    if document.owner_id == user.id:
        return True

    return DocumentAccess.objects.filter(
        document=document,
        user=user,
        permission=DocumentAccess.Permission.EDIT,
    ).exists()