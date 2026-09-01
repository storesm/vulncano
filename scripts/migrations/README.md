# Migrations

There is no Alembic here on purpose. The schema is created by `scripts/schema.mysql.sql` or
`scripts/schema.sqlite.sql` (the backend also runs the equivalent `CREATE TABLE IF NOT EXISTS`
itself on startup, so a fresh install needs nothing).

Changes to an existing database go in this directory as numbered files:

```
001_add_finding_owner.sql
002_widen_components_column.sql
```

Rules:

- One change per file, applied in numeric order, never edited after being released.
- Every statement must be safe to run twice (`ADD COLUMN IF NOT EXISTS`, or guarded by a check).
- Regenerate the schema files in the same commit: `python scripts/generate_schema.py`.
- Apply them with your usual client:

```bash
mysql -u vulncano -p vulncano < scripts/migrations/001_add_finding_owner.sql
sqlite3 ~/.vulncano/vulncano.db < scripts/migrations/001_add_finding_owner.sql
```

Back up first, `vulncano dump --out backup.sql` takes a few seconds.
