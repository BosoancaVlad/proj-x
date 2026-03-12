import mysql.connector

print("Connecting to MariaDB...")

# 1. Connect to the database server
db = mysql.connector.connect(
  host="localhost",
  user="root",
  password="bscvlad692004"
)

cursor = db.cursor()

# 2. Create the Database (The Room)
cursor.execute("CREATE DATABASE IF NOT EXISTS password_db")
cursor.execute("USE password_db")

# 3. Create the Table (The Filing Cabinet)
# Notice the "INDEX(password)" - this is the magic trick that makes searching 14 million rows instant!
cursor.execute("""
CREATE TABLE IF NOT EXISTS leaked_passwords (
    id INT AUTO_INCREMENT PRIMARY KEY,
    password VARCHAR(255) NOT NULL,
    INDEX(password)
)
""")

print("SUCCESS! Database and table are built and ready for data.")