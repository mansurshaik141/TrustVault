# TrustVault — Secure Document Sharing

TrustVault is a Django web application for sharing documents with permission controls and a tamper-evident audit trail.

## Features

- User authentication.
- Document upload with file validation.
- Private document storage.
- Owner-controlled document sharing and access revocation.
- View and edit permissions.
- Permission-checked document downloads.
- Audit logs for document activity and access attempts.
- SHA-256 hash-chained audit records.
- Signed audit checkpoints and verification.
- Automated tests for document application behavior.

## Technology

- Python 3.12
- Django 6.1.2
- SQLite
- HTML and Django templates

## Setup

Create and activate a virtual environment, then install dependencies:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Apply database migrations:

```powershell
python manage.py migrate
```

Create an administrator:

```powershell
python manage.py createsuperuser
```

Start the development server:

```powershell
python manage.py runserver
```

Open `http://127.0.0.1:8000/` in your browser.

## Tests

Run the system check:

```powershell
python manage.py check
```

Run the document tests:

```powershell
python manage.py test documents
```

Verify the audit checkpoint:

```powershell
python manage.py audit_checkpoint verify
```

The current local test run passed all 16 document tests. The audit checkpoint verification also succeeded.

## Security Notes

- Uploaded documents are stored in the private `private_uploads` directory.
- Document access is checked before downloads.
- The audit trail uses a SHA-256 hash chain and signed checkpoints.
- The audit signing key is stored outside the project directory and must remain private.
- Production deployment still requires verification of secret management, HTTPS, and private storage configuration.
- File validation does not replace malware scanning.

## Limitations

The project has been tested in a local development environment. Public deployment and production security configuration still need to be verified.

## Challenge

Developed for the Snovasys recruitment challenge.
