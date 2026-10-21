
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from documents.models import AuditLog


SECURITY_DIR = Path.home() / ".trustvault_security"
KEY_FILE = SECURITY_DIR / "audit.key"
CHECKPOINT_FILE = SECURITY_DIR / "audit_checkpoint.json"


def canonical_json(data):
    """Convert data into consistent JSON bytes for signing."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def load_signing_key():
    """Read the secret key stored outside the project."""
    try:
        key_text = KEY_FILE.read_text(encoding="utf-8").strip()
        key = bytes.fromhex(key_text)
    except (OSError, ValueError) as exc:
        raise CommandError(
            "Cannot read the signing key. Check the audit.key file."
        ) from exc

    if len(key) != 32:
        raise CommandError(
            "The signing key must contain exactly 32 random bytes."
        )

    return key


def verify_hash_chain():
    """Check every audit record and its connection to the previous record."""
    previous_hash = ""
    count = 0

    for log in AuditLog.objects.order_by("pk").iterator():
        if log.previous_hash != previous_hash:
            raise CommandError(
                f"Integrity failure: previous hash mismatch "
                f"at audit record {log.pk}."
            )

        calculated_hash = log.calculate_hash()

        if not hmac.compare_digest(
            log.record_hash,
            calculated_hash,
        ):
            raise CommandError(
                f"Integrity failure: record hash mismatch "
                f"at audit record {log.pk}."
            )

        previous_hash = log.record_hash
        count += 1

    return count, previous_hash


def read_and_verify_checkpoint(key):
    """Verify the checkpoint's signature and its database anchor."""
    try:
        saved = json.loads(
            CHECKPOINT_FILE.read_text(encoding="utf-8")
        )
        payload = saved["payload"]
        signature = saved["signature"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise CommandError(
            "Checkpoint is missing or has an invalid format."
        ) from exc

    expected_signature = hmac.new(
        key,
        canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()

    if not isinstance(signature, str) or not hmac.compare_digest(
        signature,
        expected_signature,
    ):
        raise CommandError(
            "CHECKPOINT SIGNATURE FAILED. Do not replace the checkpoint."
        )

    if payload.get("version") != 1:
        raise CommandError("Unsupported checkpoint version.")

    # Check the entire chain before trusting its anchor.
    total_count, _ = verify_hash_chain()

    last_id = payload.get("last_record_id")
    last_hash = payload.get("last_record_hash")
    saved_count = payload.get("record_count")

    if not isinstance(saved_count, int) or isinstance(saved_count, bool):
        raise CommandError("Checkpoint record count is invalid.")

    if saved_count < 0:
        raise CommandError("Checkpoint record count is invalid.")

    if last_id is None:
        if saved_count != 0 or last_hash != "":
            raise CommandError("Empty checkpoint data is inconsistent.")

        if total_count != 0:
            raise CommandError(
                "Audit records exist, but the checkpoint has no anchor."
            )
    else:
        if not isinstance(last_id, int) or isinstance(last_id, bool):
            raise CommandError("Checkpoint record ID is invalid.")

        anchor = AuditLog.objects.filter(pk=last_id).first()

        if anchor is None:
            raise CommandError(
                "Checkpoint anchor is missing from the database."
            )

        actual_count = AuditLog.objects.filter(pk__lte=last_id).count()

        if actual_count != saved_count:
            raise CommandError(
                "Checkpoint record count does not match the database."
            )

        if anchor.record_hash != last_hash:
            raise CommandError(
                "Checkpoint anchor hash does not match the database."
            )

    return payload, total_count


class Command(BaseCommand):
    help = "Create or verify a signed TrustVault audit checkpoint."

    def add_arguments(self, parser):
        parser.add_argument(
            "operation",
            choices=["create", "verify"],
            help="Create a checkpoint or verify audit integrity.",
        )

    def handle(self, *args, **options):
        operation = options["operation"]
        key = load_signing_key()

        if operation == "verify":
            if not CHECKPOINT_FILE.exists():
                raise CommandError(
                    "No checkpoint exists. Create one first."
                )

            payload, total_count = read_and_verify_checkpoint(key)

            self.stdout.write(
                self.style.SUCCESS(
                    "SUCCESS: Checkpoint signature and audit chain are valid."
                )
            )
            self.stdout.write(f"Checkpoint record count: {payload['record_count']}")
            self.stdout.write(f"Current audit record count: {total_count}")
            self.stdout.write(
                f"Checkpoint last record ID: {payload['last_record_id']}"
            )
            self.stdout.write(
                "New records after the checkpoint are allowed if the chain remains valid."
            )
            return

        # Before updating an existing checkpoint, verify it first.
        if CHECKPOINT_FILE.exists():
            read_and_verify_checkpoint(key)

        total_count, last_hash = verify_hash_chain()

        last_log = AuditLog.objects.order_by("-pk").first()

        payload = {
            "version": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "record_count": total_count,
            "last_record_id": last_log.pk if last_log else None,
            "last_record_hash": last_hash,
        }

        signature = hmac.new(
            key,
            canonical_json(payload),
            hashlib.sha256,
        ).hexdigest()

        checkpoint = {
            "payload": payload,
            "signature": signature,
        }

        SECURITY_DIR.mkdir(parents=True, exist_ok=True)
        temporary_file = CHECKPOINT_FILE.with_suffix(".tmp")

        try:
            with temporary_file.open("w", encoding="utf-8") as file:
                json.dump(checkpoint, file, indent=2)
                file.write("\n")
                file.flush()
                os.fsync(file.fileno())

            # Replace the old checkpoint only after writing the new file.
            temporary_file.replace(CHECKPOINT_FILE)
        except OSError as exc:
            raise CommandError(
                "Could not save the checkpoint file."
            ) from exc

        self.stdout.write(
            self.style.SUCCESS("Signed audit checkpoint created successfully.")
        )
        self.stdout.write(f"Audit records included: {total_count}")
        self.stdout.write(f"Last record ID: {payload['last_record_id']}")
        self.stdout.write("Checkpoint location: outside the project folder.")
