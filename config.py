import os

db = {
    "host": os.environ["POSTGRES_HOST"],
    "port": int(os.environ.get("POSTGRES_PORT", "5432")),
    "user": os.environ["POSTGRES_USER"],
    "password": os.environ["POSTGRES_PASSWORD"],
    "dbname": os.environ["POSTGRES_DB"],
}

log = {
    "level": "DEBUG",
    "file": None,
    # "file": "/var/log/tracks_server.log",
}
