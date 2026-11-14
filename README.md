# KeyGuard — Company Key Lifecycle Simulator

Run locally from this folder:

    python3 -m venv .venv
    .venv/bin/pip install -r requirements.txt
    .venv/bin/python app.py

Open http://127.0.0.1:5050. To select another port, set KEYGUARD_PORT.

| Domain | Email | Password |
|---|---|---|
| platform.example | admin@platform.example | Admin@123 |
| north.example | alice@north.example | Employee@123 |
| north.example | ben@north.example | Employee@123 |
| south.example | cara@south.example | Employee@123 |

These are pre-enrolled fictional accounts. Domain selection is checked against the exact authenticated employee record; it is not email delivery or corporate SSO. Use only test data.

1. Sign in as platform admin. Assign separate keys to the three employees.
2. Sign in as an employee, encrypt a sample, and verify and download it. Try with a second employee; each sees only their own files.
3. Open Incident Lab with no login. Generate fictional artifacts, select Alice, Ben, or Cara and test their leaked demo key against four ciphertexts, and run the tamper check. Click **Simulate stealing selected key** to create an incident for that employee’s active workspace key and enable the fictional artifact downloads. To try manually, download the lab artifacts, then upload the key and ciphertext into the lab form. No lab artifacts are uploaded to the server.
4. In the admin console, review the selected employee’s incident, revoke the affected key, and select **Rotate & recover**. This changes only the selected employee’s key and files. Confirm their files can be verified and downloaded again. Review the counts and download the audit CSV.

Flask handles server-side membership, authorization, and AES-256-GCM operations. SQLite stores account password hashes, assignments, metadata, ciphertext, incidents and audit events. Key material is in a separate permissions-restricted local directory, not a managed vault or HSM. Employees and admins see versions/statuses but receive no workspace key material. The lab uses independent browser-generated fixtures and only the explicit theft simulation records a company incident, restricted to the three seeded employee accounts. Admin and the selected employee receive in-app notices. Older demo data is left in the original instance directory; the company version starts with its own database.

Run checks: `.venv/bin/python -m pytest -q` and `node test_lab.cjs`.

See [SQLite inspection guide](SQLITE-GUIDE.md).
