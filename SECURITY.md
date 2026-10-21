# TrustVault Security Design

## 1. Authentication

TrustVault uses Django authentication to protect document-related pages. Users must log in before accessing the document list, details, editing, sharing, or download views.

## 2. Authorization and Permissions

Document access is controlled by ownership and explicit access grants.

- **Owner:** Can access the document and manage sharing and revocation.
- **View permission:** Allows viewing and downloading but does not allow editing or managing access.
- **Edit permission:** Allows viewing, downloading, and editing document details.
- **Unauthorized access:** Requests from users without permission are denied.
- **Revoked access:** Removing a user's access grant prevents subsequent authorized-view and download access.

Permission checks are performed in Django views, rather than relying only on hidden buttons in HTML templates.

## 3. File Validation and Storage

Uploaded files are validated for permitted file extensions, file size, and basic file signatures for supported file types.

Files are stored in the private `private_uploads` directory. Downloads are delivered through a permission-checked Django view. The development URL configuration does not expose a public `/media/` route.

**Limitation:** File extension and signature checks do not prove that a file is safe. The application does not currently provide dedicated malware scanning.

Production deployment must ensure that the private storage directory is not exposed by the hosting platform or web server.

## 4. Audit Logging

TrustVault records document-related activity and relevant access attempts in the audit log. Entries can include the acting user, document, action, result, timestamp, IP address, user agent, and activity details.

Audit records are linked through a SHA-256 hash chain. Each record incorporates the previous record's hash, helping detect changes to the audit history.

## 5. Signed Checkpoints

TrustVault creates signed audit checkpoints using a secret key stored outside the project directory. The checkpoint provides a signed reference to the audit history at the time it was created.

Verify the checkpoint and audit chain with:

```powershell
python manage.py audit_checkpoint verify
```

Create a new checkpoint with:

```powershell
python manage.py audit_checkpoint create
```

The current development checkpoint has been verified successfully against 57 audit records.

The audit signing key must remain private, must not be committed to version control, and should be backed up securely. If the key is compromised, the trustworthiness of signed checkpoints can be affected.

## 6. Security Testing

The current local verification includes:

- Django system check passed.
- All 16 document application tests passed.
- Unauthenticated access to protected pages was redirected to login.
- View-only users were denied document editing.
- Revoked access was denied.
- The tested public media URL returned HTTP 404.
- Audit checkpoint signature and hash-chain verification succeeded.

These results describe the current development environment. They do not establish that every possible attack or production configuration has been tested.

## 7. Production Considerations

Before production use:

- Configure HTTPS and secure cookie settings.
- Keep signing keys and other secrets outside version control.
- Ensure private uploaded files cannot be served directly by the web server.
- Use appropriate production database, backup, and access controls.
- Review deployment permissions, logging, and error handling.
- Consider malware scanning and additional security testing.

## 8. Responsible Use

TrustVault is a recruitment-challenge project. Its security features are intended to demonstrate access control and tamper-evident audit logging, not to guarantee immunity from all attacks.
