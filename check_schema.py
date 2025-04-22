import sqlite3

# Path to your database file
db_path = 'database.db'

# Connect to the database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Query the schema of the zayavka table
cursor.execute("PRAGMA table_info(zayavka);")
columns = cursor.fetchall()

# Print the schema
print("Schema of zayavka table:")
for column in columns:
    print(column)

# Close the connection
conn.close()
