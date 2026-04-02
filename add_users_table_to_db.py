import pymysql

print("Connecting to database to add Users...")
db = pymysql.connect(host="127.0.0.1", user="root", password="bscvlad692004", database="password_db")
cursor = db.cursor()

#1.Create the Users table
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL
)
""")

#2.Add a 'user_id' column to the vault so we know who owns what
try:
    cursor.execute("ALTER TABLE my_vault ADD COLUMN user_id INT")
    print("Added user_id column to my_vault.")
except Exception as e:
    print("Column might already exist, moving on!")

db.commit()
db.close()
print("SUCCESS! Your database is now ready for multiple users.")