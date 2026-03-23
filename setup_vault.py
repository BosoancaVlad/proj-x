import mysql.connector

print("Connecting to database...")

# connect to your existing database
db = mysql.connector.connect(
  host="localhost",
  user="root",
  password="bscvlad692004",  
  database="password_db"
)
cursor = db.cursor()

# create the new Vault table
cursor.execute("""
CREATE TABLE IF NOT EXISTS my_vault (
    id INT AUTO_INCREMENT PRIMARY KEY,
    website VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL
)
""")

db.commit()
print("SUCCESS! Your secure vault has been created.")