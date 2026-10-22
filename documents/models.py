
import hashlib
import json

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models, transaction


class Document(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    category = models.CharField(max_length=100, blank=True)

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="owned_documents",
    )

    uploaded_file = models.FileField(
        upload_to="private_documents/"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title


class DocumentAccess(models.Model):
    class Permission(models.TextChoices):
        VIEW = "view", "View"
        EDIT = "edit", "Edit"

    document = models.ForeignKey(
        Document,
        on_delete=models.CASCADE,
        related_name="access_grants",
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="document_access_grants",
    )

    permission = models.CharField(
        max_length=10,
        choices=Permission.choices,
        default=Permission.VIEW,
    )

    granted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["document", "user"],
                name="unique_document_user_access",
            )
        ]

    def __str__(self):
        return (
            f"{self.user} - {self.document} "
            f"({self.permission})"
        )


class AuditLog(models.Model):
    class Action(models.TextChoices):
        UPLOAD = "upload", "Document Uploaded"
        VIEW = "view", "Document Viewed"
        DOWNLOAD = "download", "Document Downloaded"
        EDIT = "edit", "Document Edited"
        DELETE = "delete", "Document Deleted"
        ACCESS_DENIED = "access_denied", "Access Denied"
        ACCESS_GRANTED = "access_granted", "Access Granted"
        ACCESS_REVOKED = "access_revoked", "Access Revoked"

    class Result(models.TextChoices):
        SUCCESS = "success", "Success"
        DENIED = "denied", "Denied"
        FAILURE = "failure", "Failure"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs",
    )

    document = models.ForeignKey(
        Document,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs",
    )

    action = models.CharField(
        max_length=20,
        choices=Action.choices,
    )

    result = models.CharField(
        max_length=10,
        choices=Result.choices,
        default=Result.SUCCESS,
    )

    timestamp = models.DateTimeField(auto_now_add=True)

    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
    )

    user_agent = models.TextField(blank=True)
    details = models.TextField(blank=True)

    # Cryptographic audit-chain fields.
    previous_hash = models.CharField(
        max_length=64,
        blank=True,
        default="",
        editable=False,
    )

    record_hash = models.CharField(
        max_length=64,
        blank=True,
        default="",
        editable=False,
    )

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(
                fields=["timestamp"],
                name="audit_timestamp_idx",
            ),
            models.Index(
                fields=["user", "timestamp"],
                name="audit_user_time_idx",
            ),
            models.Index(
                fields=["document", "timestamp"],
                name="audit_doc_time_idx",
            ),
        ]

    def calculate_hash(self):
        payload = {
            "id": self.pk,
            "user_id": self.user_id,
            "document_id": self.document_id,
            "action": self.action,
            "result": self.result,
            "timestamp": (
                self.timestamp.isoformat()
                if self.timestamp
                else None
            ),
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "details": self.details,
            "previous_hash": self.previous_hash,
        }

        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        return hashlib.sha256(encoded).hexdigest()

    @classmethod
    def verify_chain(cls):
        """
        Verify that each audit record's hash is valid
        and links to the previous record.
        Returns an empty list if the chain is valid.
        """
        errors = []
        expected_previous_hash = ""

        for entry in cls.objects.order_by("pk").iterator():
            if entry.previous_hash != expected_previous_hash:
                errors.append(
                    f"Log ID {entry.pk}: previous hash mismatch"
                )

            calculated_hash = entry.calculate_hash()

            if entry.record_hash != calculated_hash:
                errors.append(
                    f"Log ID {entry.pk}: record hash mismatch"
                )

            expected_previous_hash = entry.record_hash

        return errors

    def save(self, *args, **kwargs):
        # Existing audit records cannot be changed through save().
        if not self._state.adding:
            raise ValidationError(
                "Existing audit records cannot be modified."
            )

        # Serializes inserts on databases that support row locking
        # for the selected rows. SQLite has limited locking support;
        # robust concurrent sequencing needs a dedicated checkpoint
        # or database-specific implementation.
        with transaction.atomic():
            previous = (
                AuditLog.objects
                .order_by("-pk")
                .first()
            )

            self.previous_hash = (
                previous.record_hash if previous else ""
            )

            super().save(*args, **kwargs)

            self.record_hash = self.calculate_hash()

            # Update only the hash field after the new row exists.
            # QuerySet.update() deliberately bypasses this save().
            AuditLog.objects.filter(pk=self.pk).update(
                record_hash=self.record_hash
            )

    def delete(self, *args, **kwargs):
        raise ValidationError(
            "Audit records cannot be deleted through the model."
        )

    def __str__(self):
        return (
            f"{self.action} - {self.result} "
            f"at {self.timestamp}"
        )