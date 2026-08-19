"""Run local versioned migrations."""

from pathlib import Path
import sys

BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from sqlalchemy import text  # noqa: E402
from database import engine  # noqa: E402
from importlib.util import module_from_spec, spec_from_file_location  # noqa: E402


def main():
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE IF NOT EXISTS schema_migrations (version VARCHAR(100) PRIMARY KEY, applied_at TIMESTAMP NOT NULL)"))
        applied = {row[0] for row in connection.execute(text("SELECT version FROM schema_migrations"))}
    migrations = sorted(Path(__file__).resolve().parent.glob("[0-9][0-9][0-9]_*.py"))
    if not migrations:
        raise RuntimeError("No migration files found")
    pending = []
    for migration_path in migrations:
        spec = spec_from_file_location(f"migration_{migration_path.stem}", migration_path)
        migration = module_from_spec(spec)
        spec.loader.exec_module(migration)
        if migration.VERSION not in applied:
            migration.upgrade()
            with engine.begin() as connection:
                connection.execute(text("INSERT INTO schema_migrations(version, applied_at) VALUES (:version, CURRENT_TIMESTAMP)"), {"version": migration.VERSION})
            pending.append(migration.VERSION)
    print(f"Applied: {', '.join(pending)}" if pending else "Migrations are up to date")


if __name__ == "__main__":
    main()
