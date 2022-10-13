Upgrading FACT from 3 to 4
==========================

With the release of FACT 4.0, the database was switched from MongoDB to PostgreSQL.
To install all dependencies, simply rerun the installation::

    $ python3 src/install.py

Existing analysis and comparison results from your old FACT installation have to be migrated to the new database.
First you need to start the database::

    $ mongod --config config/mongod.conf

Then you can start the migration script::

    $ python3 src/migrate_db_to_postgresql.py

After this, you should be able to start FACT normally and should find your old data in the new database.
When the migration is complete, FACT does not use MongoDB anymore and you may want to uninstall it::

    $ python3 -m pip uninstall pymongo
    $ sudo apt remove mongodb # or mongodb-org depending on which version is installed
