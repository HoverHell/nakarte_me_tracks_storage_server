#!/usr/bin/env python3

import os
import sys

import psycopg2

import config

if __name__ == "__main__":
    connection = psycopg2.connect(**config.db)
    connection.set_session(autocommit=True)
    schema = open(os.path.join(os.path.dirname(sys.argv[0]), "init.sql")).read().split(";")
    cursor = connection.cursor()
    for st in schema:
        if st.strip():
            cursor.execute(st + ";")
