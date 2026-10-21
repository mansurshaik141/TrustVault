
import os

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.http import FileResponse, Http404, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from .forms import DocumentEditForm, DocumentUploadForm
from .models import AuditLog, Document, DocumentAccess
from .permissions import can_view_document, can_edit_document


User = get_user_model()


# Form used to share a document with another user
class ShareDocumentForm(forms.Form):
    username = forms.CharField(max_length=150)
    permission = forms.ChoiceField(
        choices=DocumentAccess.Permission.choices
    )


# Check whether the current user owns the document or is an admin
def is_owner_or_admin(user, document):
    return user.is_authenticated and (
        user.is_superuser or document.owner_id == user.id
    )


# Record document activity in the audit log
def log_document_activity(
    request,
    action,
    result,
    document=None,
    details="",
):
    AuditLog.objects.create(
        user=request.user if request.user.is_authenticated else None,
        document=document,
        action=action,
        result=result,
        ip_address=request.META.get("REMOTE_ADDR"),
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
        details=details,
    )


# 1. Display the documents the user can access
@login_required
def document_list(request):
    if request.user.is_superuser:
        documents = Document.objects.select_related("owner").all()
    else:
        documents = Document.objects.filter(
            Q(owner=request.user)
            | Q(access_grants__user=request.user)
        ).select_related("owner").distinct()

    search_query = request.GET.get("q", "").strip()

    if search_query:
        documents = documents.filter(
            Q(title__icontains=search_query)
            | Q(description__icontains=search_query)
            | Q(category__icontains=search_query)
        )

    return render(
        request,
        "documents/document_list.html",
        {
            "documents": documents,
            "search_query": search_query,
        },
    )


# 2. Upload a new document
@login_required
def document_upload(request):
    if request.method == "POST":
        form = DocumentUploadForm(request.POST, request.FILES)

        if form.is_valid():
            document = None

            try:
                document = form.save(commit=False)
                document.owner = request.user
                document.save()

                log_document_activity(
                    request,
                    AuditLog.Action.UPLOAD,
                    AuditLog.Result.SUCCESS,
                    document=document,
                    details="Document uploaded successfully",
                )

                return redirect(
                    "documents:detail",
                    document_id=document.id,
                )

            except Exception:
                log_document_activity(
                    request,
                    AuditLog.Action.UPLOAD,
                    AuditLog.Result.FAILURE,
                    document=document,
                    details="Document upload failed during saving",
                )
                raise

        log_document_activity(
            request,
            AuditLog.Action.UPLOAD,
            AuditLog.Result.FAILURE,
            details="Document upload rejected: form validation failed",
        )

    else:
        form = DocumentUploadForm()

    return render(
        request,
        "documents/document_upload.html",
        {"form": form},
    )


# 3. Display document details
@login_required
def document_detail(request, document_id):
    document = get_object_or_404(Document, pk=document_id)

    if not can_view_document(request.user, document):
        log_document_activity(
            request,
            AuditLog.Action.ACCESS_DENIED,
            AuditLog.Result.DENIED,
            document=document,
            details="Unauthorized document view attempt",
        )
        raise Http404("Document not found.")

    log_document_activity(
        request,
        AuditLog.Action.VIEW,
        AuditLog.Result.SUCCESS,
        document=document,
        details="Document details viewed",
    )

    can_manage = is_owner_or_admin(request.user, document)

    share_form = ShareDocumentForm() if can_manage else None

    grants = (
        document.access_grants.select_related("user").all()
        if can_manage
        else []
    )

    return render(
        request,
        "documents/document_detail.html",
        {
            "document": document,
            "can_manage": can_manage,
            "can_edit": can_edit_document(request.user, document),
            "share_form": share_form,
            "grants": grants,
        },
    )


# 4. Download a document
@login_required
def document_download(request, document_id):
    document = get_object_or_404(Document, pk=document_id)

    if not can_view_document(request.user, document):
        log_document_activity(
            request,
            AuditLog.Action.ACCESS_DENIED,
            AuditLog.Result.DENIED,
            document=document,
            details="Unauthorized document download attempt",
        )
        raise Http404("Document not found.")

    try:
        document_file = document.uploaded_file
        document_file.open("rb")

        response = FileResponse(
            document_file,
            as_attachment=True,
            filename=os.path.basename(document_file.name),
        )

        log_document_activity(
            request,
            AuditLog.Action.DOWNLOAD,
            AuditLog.Result.SUCCESS,
            document=document,
            details="Document downloaded successfully",
        )

        return response

    except (FileNotFoundError, OSError, ValueError):
        log_document_activity(
            request,
            AuditLog.Action.DOWNLOAD,
            AuditLog.Result.FAILURE,
            document=document,
            details="Document download failed: file unavailable",
        )
        raise Http404("The document file is unavailable.")


# 5. Check whether the user has permission to edit a document
@login_required
def document_edit_check(request, document_id):
    document = get_object_or_404(Document, pk=document_id)

    # Check whether the user has permission to edit.
    if not can_edit_document(request.user, document):
        log_document_activity(
            request,
            AuditLog.Action.ACCESS_DENIED,
            AuditLog.Result.DENIED,
            document=document,
            details="Unauthorized document edit attempt",
        )
        return HttpResponseForbidden(
            "You do not have permission to edit this document."
        )

    if request.method == "POST":
        edit_form = DocumentEditForm(
            request.POST,
            instance=document,
        )

        if edit_form.is_valid():
            edit_form.save()

            log_document_activity(
                request,
                AuditLog.Action.EDIT,
                AuditLog.Result.SUCCESS,
                document=document,
                details="Document details updated successfully",
            )

            return redirect(
                "documents:detail",
                document_id=document.pk,
            )

        log_document_activity(
            request,
            AuditLog.Action.EDIT,
            AuditLog.Result.FAILURE,
            document=document,
            details="Document edit failed: invalid form data",
        )
    else:
        edit_form = DocumentEditForm(instance=document)

    return render(
        request,
        "documents/document_edit.html",
        {
            "document": document,
            "edit_form": edit_form,
        },
    )



# 6. Share a document with another user
@login_required
@require_POST
def document_share(request, document_id):
    document = get_object_or_404(Document, pk=document_id)

    if not is_owner_or_admin(request.user, document):
        log_document_activity(
            request,
            AuditLog.Action.ACCESS_DENIED,
            AuditLog.Result.DENIED,
            document=document,
            details="Unauthorized document sharing attempt",
        )
        return HttpResponseForbidden(
            "Only the document owner or an admin can share this document."
        )

    form = ShareDocumentForm(request.POST)

    if not form.is_valid():
        log_document_activity(
            request,
            AuditLog.Action.ACCESS_GRANTED,
            AuditLog.Result.FAILURE,
            document=document,
            details="Document sharing failed: invalid form data",
        )
        return redirect(
            "documents:detail",
            document_id=document.id,
        )

    try:
        recipient = User.objects.get(
            username=form.cleaned_data["username"]
        )
    except User.DoesNotExist:
        log_document_activity(
            request,
            AuditLog.Action.ACCESS_GRANTED,
            AuditLog.Result.FAILURE,
            document=document,
            details="Document sharing failed: recipient does not exist",
        )

        form.add_error(
            "username",
            "No user with that username exists.",
        )

        return render(
            request,
            "documents/document_detail.html",
            {
                "document": document,
                "can_manage": True,
                "can_edit": can_edit_document(request.user, document),
                "share_form": form,
                "grants": document.access_grants.select_related("user").all(),
            },
            status=400,
        )

    if recipient.pk == document.owner_id or recipient.is_superuser:
        log_document_activity(
            request,
            AuditLog.Action.ACCESS_GRANTED,
            AuditLog.Result.FAILURE,
            document=document,
            details="Document sharing failed: invalid recipient",
        )

        form.add_error(
            "username",
            "Choose another regular user.",
        )

        return render(
            request,
            "documents/document_detail.html",
            {
                "document": document,
                "can_manage": True,
                "can_edit": can_edit_document(request.user, document),
                "share_form": form,
                "grants": document.access_grants.select_related("user").all(),
            },
            status=400,
        )

    DocumentAccess.objects.update_or_create(
        document=document,
        user=recipient,
        defaults={
            "permission": form.cleaned_data["permission"],
        },
    )

    log_document_activity(
        request,
        AuditLog.Action.ACCESS_GRANTED,
        AuditLog.Result.SUCCESS,
        document=document,
        details="Document access granted or updated",
    )

    return redirect(
        "documents:detail",
        document_id=document.id,
    )


# 7. Revoke a user's access to a document
@login_required
@require_POST
def document_revoke(request, document_id, user_id):
    document = get_object_or_404(Document, pk=document_id)

    if not is_owner_or_admin(request.user, document):
        log_document_activity(
            request,
            AuditLog.Action.ACCESS_DENIED,
            AuditLog.Result.DENIED,
            document=document,
            details="Unauthorized document access revocation attempt",
        )
        return HttpResponseForbidden(
            "Only the document owner or an admin can revoke access."
        )

    access_grant = DocumentAccess.objects.filter(
        document=document,
        user_id=user_id,
    ).first()

    if access_grant is None:
        log_document_activity(
            request,
            AuditLog.Action.ACCESS_REVOKED,
            AuditLog.Result.FAILURE,
            document=document,
            details="Access revocation failed: access grant not found",
        )
        return redirect(
            "documents:detail",
            document_id=document.id,
        )

    access_grant.delete()

    log_document_activity(
        request,
        AuditLog.Action.ACCESS_REVOKED,
        AuditLog.Result.SUCCESS,
        document=document,
        details=f"Document access revoked for user ID {user_id}",
    )

    return redirect(
        "documents:detail",
        document_id=document.id,
    )
