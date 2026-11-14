# Inspect the KeyGuard backend

On the Mac running KeyGuard, open Terminal. If your project folder is somewhere else, replace the path on the first line.

    cd "/Users/sumukhhebbar/Documents/Codex/2026-10-23/th/outputs/key-lifecycle-simulator"
    sqlite3 -readonly instance-v2/simulator.db

The database is created the first time the rebuilt app runs. Once at the SQLite prompt:

    .tables
    .headers on
    .mode column
    .schema keys

See the companies and the employee accounts (no password hashes):

    SELECT c.domain, u.email, u.role
    FROM users u JOIN companies c ON c.id = u.company_id
    ORDER BY c.domain, u.email;

See assigned key versions without opening any key files:

    SELECT c.domain, u.email, k.version, k.status
    FROM keys k
    JOIN users u ON u.id = k.user_id
    JOIN companies c ON c.id = k.company_id
    ORDER BY c.domain, u.email, k.version;

See stored ciphertext size and which key version protects each file:

    SELECT f.name, k.version, f.size AS original_bytes,
           length(f.ciphertext) AS encrypted_bytes
    FROM files f JOIN keys k ON k.id = f.key_id;

See the last ten events:

    SELECT created_at, actor, event, detail
    FROM audit ORDER BY id DESC LIMIT 10;

Type `.quit` to exit. You can also open the file in an installed SQLite GUI in read-only mode. The Python backend is in `app.py`. The database contains account hashes and encrypted files; the separate `instance-v2/keys/` directory holds secret key material. For a classmate running their own copy, share the source ZIP and have them start the app to create a fresh local database.
