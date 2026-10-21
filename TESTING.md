# TrustVault Testing Report

## 1. Test Environment

- Operating system: Windows
- Python: 3.12.10
- Django: 6.1.2
- Database: SQLite
- Testing framework: Django test framework

## 2. Automated Test Results

The following commands were executed locally.

### Django system check

Command:

```powershell
python manage.py check
```

Result: **PASS**

Output confirmed that Django identified no system-check issues.

### Document application tests

Command:

```powershell
python manage.py test documents
```

Result: **PASS — 16 of 16 tests**

The test runner reported that all 16 tests passed, with no failures.

## 3. Manual Security Checks

| Test | Observed result |
|---|---|
| Unauthenticated access to document list | Redirected to login |
| Unauthenticated access to document details | Redirected to login |
| Unauthenticated direct download | Redirected to login |
| View-only user attempts to edit | Denied |
| View-only user downloads an authorized document | Allowed, as intended |
| Revoked user attempts to access the document | Denied |
| Tested public media URL | HTTP 404 |
| Owner document page | Edit and sharing controls displayed |
| Audit checkpoint verification | Passed |

## 4. Audit Integrity Verification

The command below was run after creating a signed checkpoint:

```powershell
python manage.py audit_checkpoint verify
```

Observed result: **SUCCESS**

At the time of the latest verification:

- Checkpoint record count: 57
- Current audit record count: 57
- Last checkpoint record ID: 57
- Checkpoint signature and audit chain: valid

## 5. Scope and Limitations

These results reflect testing performed in the local development environment. The 16 automated tests passed, and the manual checks listed above produced the expected results.

The tested public media URL returning HTTP 404 confirms that the URL was not served through that tested route. It does not, by itself, prove that every possible production server configuration protects private files.

The project has not yet been fully validated in a public production deployment. Further deployment security checks are required before production use.

## 6. Summary

TrustVault passed the current Django system check, all 16 automated document tests, and the recorded audit checkpoint verification. The manual tests also confirmed several expected access-control behaviors. Further production validation remains necessary.
