
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse

from documents.models import AuditLog, Document, DocumentAccess


User = get_user_model()


class DocumentSecurityTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            username="owner_test",
            password="TestPassword123!",
        )
        self.viewer = User.objects.create_user(
            username="viewer_test",
            password="TestPassword123!",
        )
        self.stranger = User.objects.create_user(
            username="stranger_test",
            password="TestPassword123!",
        )
        self.document = Document.objects.create(
            title="Security test document",
            owner=self.owner,
        )

    def grant_view_access(self):
        DocumentAccess.objects.update_or_create(
            document=self.document,
            user=self.viewer,
            defaults={"permission": DocumentAccess.Permission.VIEW},
        )

    def test_owner_can_open_document(self):
        self.client.force_login(self.owner)
        response = self.client.get(
            reverse(
                "documents:detail",
                kwargs={"document_id": self.document.pk},
            ),
            HTTP_HOST="localhost",
        )
        self.assertEqual(response.status_code, 200)

    def test_viewer_can_open_document_when_granted_access(self):
        self.grant_view_access()
        self.client.force_login(self.viewer)
        response = self.client.get(
            reverse(
                "documents:detail",
                kwargs={"document_id": self.document.pk},
            ),
            HTTP_HOST="localhost",
        )
        self.assertEqual(response.status_code, 200)

    def test_stranger_cannot_open_document(self):
        self.client.force_login(self.stranger)
        response = self.client.get(
            reverse(
                "documents:detail",
                kwargs={"document_id": self.document.pk},
            ),
            HTTP_HOST="localhost",
        )
        self.assertEqual(response.status_code, 404)

    def test_viewer_cannot_edit_document(self):
        self.grant_view_access()
        self.client.force_login(self.viewer)
        response = self.client.get(
            reverse(
                "documents:edit",
                kwargs={"document_id": self.document.pk},
            ),
            HTTP_HOST="localhost",
        )
        self.assertEqual(response.status_code, 403)

    def test_revoked_view_access_blocks_document(self):
        self.grant_view_access()
        DocumentAccess.objects.filter(
            document=self.document,
            user=self.viewer,
        ).delete()

        self.client.force_login(self.viewer)
        response = self.client.get(
            reverse(
                "documents:detail",
                kwargs={"document_id": self.document.pk},
            ),
            HTTP_HOST="localhost",
        )
        self.assertEqual(response.status_code, 404)


class AuditLogModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="audit_test_user",
            password="TestPassword123!",
        )
        self.document = Document.objects.create(
            title="Audit test document",
            owner=self.user,
        )

    def test_invalid_checkpoint_signature_is_rejected(self):
        import json
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        from django.core.management.base import CommandError
        from documents.management.commands.audit_checkpoint import (
            read_and_verify_checkpoint,
        )

        fake_checkpoint = {
            "payload": {
                "version": 1,
                "record_count": 0,
                "last_record_id": None,
                "last_record_hash": "",
            },
            "signature": "invalid-signature",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            checkpoint_path = Path(temp_dir) / "test_checkpoint.json"
            checkpoint_path.write_text(
                json.dumps(fake_checkpoint),
                encoding="utf-8",
            )

            with patch(
                "documents.management.commands.audit_checkpoint.CHECKPOINT_FILE",
                checkpoint_path,
            ):
                with self.assertRaisesRegex(
                    CommandError,
                    "CHECKPOINT SIGNATURE FAILED",
                ):
                    read_and_verify_checkpoint(b"test-key-for-unit-test")


    def test_audit_log_is_saved_successfully(self):
        log = AuditLog.objects.create(
            user=self.user,
            document=self.document,
            action=AuditLog.Action.VIEW,
            result=AuditLog.Result.SUCCESS,
            details="Document viewed successfully",
        )

        self.assertIsNotNone(log.pk)
        self.assertEqual(log.action, AuditLog.Action.VIEW)
        self.assertEqual(log.result, AuditLog.Result.SUCCESS)
        self.assertEqual(log.user, self.user)
        self.assertEqual(log.document, self.document)
        self.assertIsNotNone(log.timestamp)

    def test_audit_log_can_record_denied_access(self):
        log = AuditLog.objects.create(
            user=self.user,
            document=self.document,
            action=AuditLog.Action.ACCESS_DENIED,
            result=AuditLog.Result.DENIED,
            details="Access was denied",
        )

        saved_log = AuditLog.objects.get(pk=log.pk)

        self.assertEqual(
            saved_log.action,
            AuditLog.Action.ACCESS_DENIED,
        )
        self.assertEqual(
            saved_log.result,
            AuditLog.Result.DENIED,
        )

    def test_audit_log_hash_detects_tampering(self):
        log = AuditLog.objects.create(
            user=self.user,
            document=self.document,
            action=AuditLog.Action.VIEW,
            result=AuditLog.Result.SUCCESS,
            details="Original audit details",
        )

        original_hash = log.record_hash
        self.assertTrue(original_hash)

        # Simulate direct database tampering in the test database.
        AuditLog.objects.filter(pk=log.pk).update(
            details="Tampered audit details",
        )

        tampered_log = AuditLog.objects.get(pk=log.pk)

        # The stored hash should no longer match the changed record.
        self.assertNotEqual(
            tampered_log.record_hash,
            tampered_log.calculate_hash(),
        )
        from django.core.management.base import CommandError
        from documents.management.commands.audit_checkpoint import (
            verify_hash_chain,
        )

        with self.assertRaises(CommandError):
            verify_hash_chain()

    def test_existing_audit_log_cannot_be_modified_with_save(self):
        from django.core.exceptions import ValidationError

        log = AuditLog.objects.create(
            user=self.user,
            document=self.document,
            action=AuditLog.Action.VIEW,
            result=AuditLog.Result.SUCCESS,
            details="Original audit details",
        )

        log.details = "Attempted modification"

        with self.assertRaises(ValidationError):
            log.save()

    def test_verify_chain_detects_broken_previous_hash(self):
        first_log = AuditLog.objects.create(
            action=AuditLog.Action.VIEW,
            result=AuditLog.Result.SUCCESS,
            details="First audit record",
        )

        second_log = AuditLog.objects.create(
            action=AuditLog.Action.DOWNLOAD,
            result=AuditLog.Result.SUCCESS,
            details="Second audit record",
        )

        # Simulate database tampering in the isolated test database.
        AuditLog.objects.filter(pk=second_log.pk).update(
            previous_hash="broken_test_hash",
        )

        errors = AuditLog.verify_chain()

        self.assertTrue(
            any("previous hash mismatch" in error for error in errors),
            f"Expected a broken-link error, but received: {errors}",
        )



class AuditTrailViewTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            username="audit_owner",
            password="TestPassword123!",
        )
        self.stranger = User.objects.create_user(
            username="audit_stranger",
            password="TestPassword123!",
        )
        self.document = Document.objects.create(
            title="Audit trail test document",
            owner=self.owner,
        )

    def test_access_revocation_is_logged(self):
        grant = DocumentAccess.objects.create(
            document=self.document,
            user=self.stranger,
            permission=DocumentAccess.Permission.VIEW,
        )

        self.client.force_login(self.owner)
        response = self.client.post(
            reverse(
                "documents:revoke",
                kwargs={
                    "document_id": self.document.pk,
                    "user_id": self.stranger.pk,
                },
            ),
            HTTP_HOST="localhost",
        )

        self.assertEqual(response.status_code, 302)
        self.assertFalse(
            DocumentAccess.objects.filter(pk=grant.pk).exists()
        )
        self.assertTrue(
            AuditLog.objects.filter(
                user=self.owner,
                document=self.document,
                action=AuditLog.Action.ACCESS_REVOKED,
                result=AuditLog.Result.SUCCESS,
            ).exists()
        )

    def test_successful_document_view_is_logged(self):
        self.client.force_login(self.owner)
        response = self.client.get(
            reverse(
                "documents:detail",
                kwargs={"document_id": self.document.pk},
            ),
            HTTP_HOST="localhost",
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            AuditLog.objects.filter(
                user=self.owner,
                document=self.document,
                action=AuditLog.Action.VIEW,
                result=AuditLog.Result.SUCCESS,
            ).exists()
        )

    def test_denied_document_view_is_logged(self):
        self.client.force_login(self.stranger)
        response = self.client.get(
            reverse(
                "documents:detail",
                kwargs={"document_id": self.document.pk},
            ),
            HTTP_HOST="localhost",
        )

        self.assertEqual(response.status_code, 404)
        self.assertTrue(
            AuditLog.objects.filter(
                user=self.stranger,
                document=self.document,
                action=AuditLog.Action.ACCESS_DENIED,
                result=AuditLog.Result.DENIED,
            ).exists()
        )

    def test_invalid_upload_is_logged(self):
        from django.core.files.uploadedfile import SimpleUploadedFile

        self.client.force_login(self.owner)

        bad_file = SimpleUploadedFile(
            "malware.exe",
            b"test data",
            content_type="application/octet-stream",
        )

        response = self.client.post(
            reverse("documents:upload"),
            {
                "title": "Invalid Upload Test",
                "description": "",
                "category": "Testing",
                "uploaded_file": bad_file,
            },
            HTTP_HOST="localhost",
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(
            Document.objects.filter(
                title="Invalid Upload Test",
                owner=self.owner,
            ).exists()
        )
        self.assertTrue(
            AuditLog.objects.filter(
                user=self.owner,
                action=AuditLog.Action.UPLOAD,
                result=AuditLog.Result.FAILURE,
                details="Document upload rejected: form validation failed",
            ).exists()
        )

    def test_failed_sharing_attempt_is_logged(self):
        self.client.force_login(self.owner)

        response = self.client.post(
            reverse(
                "documents:share",
                kwargs={"document_id": self.document.pk},
            ),
            {
                "username": "missing_user_987",
                "permission": "view",
            },
            HTTP_HOST="localhost",
        )

        self.assertEqual(response.status_code, 400)
        self.assertTrue(
            AuditLog.objects.filter(
                user=self.owner,
                document=self.document,
                action=AuditLog.Action.ACCESS_GRANTED,
                result=AuditLog.Result.FAILURE,
                details="Document sharing failed: recipient does not exist",
            ).exists()
        )

    def test_unauthorized_download_is_logged(self):
        self.client.force_login(self.stranger)

        response = self.client.get(
            reverse(
                "documents:download",
                kwargs={"document_id": self.document.pk},
            ),
            HTTP_HOST="localhost",
        )

        self.assertEqual(response.status_code, 404)
        self.assertTrue(
            AuditLog.objects.filter(
                user=self.stranger,
                document=self.document,
                action=AuditLog.Action.ACCESS_DENIED,
                result=AuditLog.Result.DENIED,
                details="Unauthorized document download attempt",
            ).exists()
        )
