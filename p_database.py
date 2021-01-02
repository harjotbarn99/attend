import sqlite3
import bcrypt


db="z_database.db"
conn=sqlite3.connect(db)
cur=conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS users (username,password,email,phoneNumber) ")

def add_creds(username,password,email,phoneNumber):
  passwordHash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
  cur.execute(" INSERT INTO users VALUES (?,?,?,?) ",(username,passwordHash,email,phoneNumber))
  conn.commit()
  return


def check_username(username):
  for user in cur.execute("SELECT * FROM users WHERE username = ? ",(username,)):
    return True


def check_email(email):
  for user in cur.execute("SELECT * FROM users WHERE email = ? ",(email,)):
    return True


def validate_creds(username,password):
  for user in cur.execute("SELECT * FROM users WHERE username = ? ",(username,)):
    return bcrypt.checkpw(password.encode(), user[1])