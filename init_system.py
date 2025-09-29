from DB import db_init, clear_db
from keysGeneration import generate_keys


# CLEAR DATABASE (if exists)
clear_db()

# INITIALIZE DATABASE
generate_keys()
db_init()
