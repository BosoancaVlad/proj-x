import mysql.connector
import time

print("Connecting to database...")
db = mysql.connector.connect(
  host="localhost",
  user="root",
  password="bscvlad692004", 
  database="password_db"
)
cursor = db.cursor()

print("Clearing out the old incomplete data...")
cursor.execute("TRUNCATE TABLE leaked_passwords")

insert_query = "INSERT INTO leaked_passwords (password) VALUES (%s)"
chunk_size = 50000
passwords_bucket = []
total_inserted = 0

print("Starting to read rockyou.txt... This will take a few minutes!")
start_time = time.time()

with open("rockyou.txt", "r", encoding="utf-8", errors="ignore") as file:
    for line in file:
        password = line.strip() 
        
        if password and len(password) <= 255: 
            passwords_bucket.append((password,)) 

        if len(passwords_bucket) >= chunk_size:
            cursor.executemany(insert_query, passwords_bucket)
            db.commit() 
            total_inserted += len(passwords_bucket)
            print(f"Inserted {total_inserted} passwords so far...")
            passwords_bucket = [] 

if passwords_bucket:
    cursor.executemany(insert_query, passwords_bucket)
    db.commit()
    total_inserted += len(passwords_bucket)

end_time = time.time()
print(f"\nDONE! Successfully inserted {total_inserted} valid passwords in {round((end_time - start_time) / 60, 2)} minutes.")