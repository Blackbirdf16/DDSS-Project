#!/usr/bin/env python3
"""Database initialization script for FairRide PostgreSQL setup.

Sets up database and tables for production deployment.
Can be run standalone or as part of deployment pipeline.

Usage:
    python init_db.py [--connection-string postgresql://user:pass@host:5432/dbname]
"""

import sys
import argparse
from sud.database import PostgresDB


def main():
    parser = argparse.ArgumentParser(description="Initialize FairRide PostgreSQL database")
    parser.add_argument(
        "--connection-string",
        help="PostgreSQL connection string (default from FAIRRIDE_DB_URL env var)",
        default=None
    )
    parser.add_argument(
        "--drop-existing",
        action="store_true",
        help="WARNING: Drop existing tables and recreate (clears all data)"
    )
    args = parser.parse_args()

    try:
        print("Connecting to PostgreSQL...")
        db = PostgresDB(connection_string=args.connection_string)
        
        if args.drop_existing:
            print("WARNING: Dropping existing tables...")
            db.cursor.execute("DROP TABLE IF EXISTS trips CASCADE;")
            db.cursor.execute("DROP TABLE IF EXISTS users CASCADE;")
            db.conn.commit()
            print("  ✓ Dropped existing tables")
        
        print("Creating schema...")
        db._ensure_schema()
        print("  ✓ Users table created")
        print("  ✓ Trips table created")
        print("  ✓ Indexes created")
        
        print("\n✅ Database initialized successfully!")
        print("Connection string: " + (args.connection_string or "from FAIRRIDE_DB_URL env var"))
        
        db.close()
        return 0
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
