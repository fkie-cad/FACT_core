#!/usr/bin/env python3

import argparse
import sqlite3
import uuid

from helperFunctions.config import load_config


def upgrade(cur):
    # Generate uniquifiers for already existing users
    cur.execute('ALTER TABLE user ADD COLUMN fs_uniquifier VARCHAR(64)')
    users = [row[0] for row in cur.execute('SELECT id FROM user')]
    for uid in users:
        cur.execute('UPDATE user SET fs_uniquifier = ? WHERE user.id = ?', (uuid.uuid4().hex, uid))

    # Due to limitations in SQLite we have to create a temporary table
    # We can't use ALTER TABLE to change fs_uniquifier from beeing NULLable to
    # NOT NULL
    cur.execute(
        '''
        CREATE TABLE "user_tmp" (
            "id"			INTEGER NOT NULL,
            "api_key"		VARCHAR(255) UNIQUE,
            "email"			VARCHAR(255) UNIQUE,
            "password"		VARCHAR(255),
            "active"		BOOLEAN,
            "confirmed_at"	DATETIME,
            "fs_uniquifier"	VARCHAR(64) NOT NULL UNIQUE,
            CHECK(active IN (0,1)),
            PRIMARY KEY("id"),
        );''',
    )
    cur.execute('INSERT INTO "user_tmp" SELECT * FROM "user" WHERE true')
    cur.execute('DROP TABLE "user"')
    cur.execute('ALTER TABLE "user_tmp" RENAME TO "user"')

    print('Successfully upgraded the database')


def downgrade(cur):
    # Due to limitations in SQLite we have to create a temporary table
    # We can't DROP COLUMN fs_uniquifier because it is unique
    cur.execute(
        '''
        CREATE TABLE "user_tmp" (
            "id"			INTEGER NOT NULL,
            "api_key"		VARCHAR(255) UNIQUE,
            "email"			VARCHAR(255) UNIQUE,
            "password"		VARCHAR(255),
            "active"		BOOLEAN,
            "confirmed_at"	DATETIME,
            CHECK(active IN (0,1)),
            PRIMARY KEY("id"),
        );''',
    )
    cur.execute(
        'INSERT INTO "user_tmp" SELECT id, api_key, email, password, active, confirmed_at FROM "user" WHERE true',
    )
    cur.execute('DROP TABLE "user"')
    cur.execute('ALTER TABLE "user_tmp" RENAME TO "user"')

    print('Successfully downgraded the database')


def main():
    parser = argparse.ArgumentParser()
    parser.set_defaults(func=lambda _: parser.print_usage())
    subparsers = parser.add_subparsers()

    upgrade_process = subparsers.add_parser(
        'upgrade',
        help='Upgrade the user database',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    upgrade_process.set_defaults(func=upgrade)

    downgrade_process = subparsers.add_parser(
        'downgrade',
        help='Downgrade the user database',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    downgrade_process.set_defaults(func=downgrade)
    args = parser.parse_args()

    config = load_config('main.cfg')

    db_path = config['data-storage']['user-database'][len('sqlite:///'):]

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    args.func(cur)

    conn.commit()
    conn.close()


if __name__ == '__main__':
    main()
