
from pathlib import Path

from django.core.exceptions import ValidationError


MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

ALLOWED_EXTENSIONS = {".pdf", ".txt", ".png", ".jpg", ".jpeg"}


def validate_document_file(uploaded_file):
    extension = Path(uploaded_file.name).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise ValidationError(
            "Allowed file types: PDF, TXT, PNG, JPG, JPEG."
        )

    if uploaded_file.size > MAX_FILE_SIZE:
        raise ValidationError("Maximum file size is 5 MB.")

    # Check basic file signatures, not just the filename.
    header = uploaded_file.read(16)
    uploaded_file.seek(0)

    if extension == ".pdf" and not header.startswith(b"%PDF-"):
        raise ValidationError("The file does not appear to be a valid PDF.")

    if extension == ".png" and not header.startswith(
        b"\x89PNG\r\n\x1a\n"
    ):
        raise ValidationError("The file does not appear to be a valid PNG.")

    if extension in {".jpg", ".jpeg"} and not header.startswith(b"\xff\xd8\xff"):
        raise ValidationError("The file does not appear to be a valid JPEG.")

    if extension == ".txt":
        content = uploaded_file.read()
        uploaded_file.seek(0)

        if b"\x00" in content:
            raise ValidationError("The text file contains invalid data.")
