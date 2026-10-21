# TrustVault Demo Script

## Objective

Demonstrate secure document sharing, permission enforcement, private downloads, and audit-trail verification.

## Before the Demo

- Start the application in the configured development environment.
- Open the local site at `http://127.0.0.1:8000/`.
- Use test accounts and non-sensitive sample documents only.
- Do not display or share the audit signing key.
- Avoid showing real personal documents or passwords.

## Demonstration Steps

### 1. Log In

Log in as the document owner and show the document list.

**Explain:** TrustVault uses authentication to protect document-related pages.

### 2. Upload a Document

Upload a harmless sample PDF or text file.

**Explain:** The application validates supported file types and size before saving the document in private storage.

### 3. View and Download

Open the document details and download the file.

**Explain:** Downloads are handled through a Django view that checks the user's permission.

### 4. Share Access

From the owner's document page, grant a test user view permission.

Log in as that test user in a separate browser session and open the shared document. Confirm that the user can view and download it.

**Explain:** View permission allows viewing and downloading but does not permit editing or managing sharing.

### 5. Test Permission Enforcement

As the view-only user, attempt to edit the document details.

**Expected result:** The application denies the edit attempt.

### 6. Revoke Access

Return to the owner session and revoke the test user's access.

As the test user, attempt to open the document again.

**Expected result:** Access is denied after revocation.

### 7. Verify the Audit Trail

In the terminal, run:

```powershell
python manage.py audit_checkpoint verify
```

**Explain:** The command checks the audit chain and the signed checkpoint.

### 8. Show the Test Results

Run:

```powershell
python manage.py check
python manage.py test documents
```

The latest recorded local run passed the system check and all 16 document tests.

## Closing Statement

TrustVault demonstrates authenticated document access, owner-controlled sharing, view/edit permissions, private file delivery, and a verifiable audit trail. The current results are from local testing; production deployment and its security configuration must be verified separately.
