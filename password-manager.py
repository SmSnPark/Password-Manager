import sqlite3
import os.path
import os
from passlib.hash import bcrypt
from getpass import getpass
import secrets
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#global
hasher = bcrypt.using(rounds=13)
backend = default_backend()
iterations = 100_000


def initialize_pword():
    while True:
        password = getpass()
        print("Please enter again.")
        verify = getpass()
        
        if not password == verify:
            print("Failed to enter same password twice. Try again.")
            continue
        
        return password
    
def key_check():
    while not os.path.isfile("key.key"):
        print("Looks like you don't have a password setup! To use this app, you must have this setup. This key is linked to the active database stored locally.\nPlease enter a password (secure!) that you want to use.")
        print("Make sure to have what you entered stored safely! This password is linked to the local storage. If you lose this, you will need to delete your local memory (password and database) and start over!")
        hashed = hasher.hash(initialize_pword())
        
        f = open("key.key", "w")
        f.write(hashed)
        f.close() 
        
def db_check():
    if not os.path.isfile("local-storage.db"):
        print("Looks like you don't have a database set up! I've created a fresh one for you!")
        
        d_con = sqlite3.connect("local-storage.db")
        d_cur = d_con.cursor()
        
        d_cur.execute("CREATE TABLE logs(id TEXT PRIMARY KEY, pw TEXT)")
        
        d_cur.close()
        
def _derive_key(password: bytes, salt: bytes, iterations: int = iterations) -> bytes:
    """Derive a secret key from a given password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=iterations, backend=backend)
    return b64e(kdf.derive(password))
              
def password_encrypt(message: bytes, password: str, iterations: int = iterations) -> bytes:
    salt = secrets.token_bytes(16)
    key = _derive_key(password.encode(), salt, iterations)
    return b64e(
        b'%b%b%b' % (
            salt,
            iterations.to_bytes(4, 'big'),
            b64d(Fernet(key).encrypt(message)),
        )
    )
    
def password_decrypt(token: bytes, password: str) -> bytes:
    decoded = b64d(token)
    salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iter, 'big')
    key = _derive_key(password.encode(), salt, iterations)
    return Fernet(key).decrypt(token)


if __name__=='__main__':
    _ = key_check()
    _ = db_check()

    #password check
    fr = open("key.key", "r")
    userpass = getpass()
    while not hasher.verify(userpass, fr.read()):
        print("Wrong password.\n If you forgot your password, please delete the db and key file in directory. Yes, you lose all your other passwords.")
    fr.close()
    
    #start connection with database
    con = sqlite3.connect("local-storage.db")
    cur = con.cursor()
    
    #main menu
    while 1:
        selection = input("Please choose an option:\n1. Store a new entry.\n2. Delete a entry.\n3. Retrieve a entry.\n4. Exit.\n")
    
        if (selection == '1'):
            try:
                id = input("Enter case-sensitive name of service password is for (keep it short and easy to remember).\n")
                pw = input("Enter password for service.\n")
                
                en_pw = password_encrypt(pw.encode(), userpass)
                
                SQLCommand = ("INSERT INTO logs VALUES(?,?)")
                vals = [id, en_pw]
                cur.execute(SQLCommand, vals)
                con.commit()
                
                print("Entry added.\n")
            except:
                print("Duplicate service, failed to submit entry!\n")
            
        
        elif (selection == '2'):
            to_del = input("Enter case-sensitive name of service to delete.\n")
            cur.execute("DELETE FROM logs WHERE id = '" + to_del + "'")
            con.commit()
            
        
        elif (selection == '3'):
            to_pull = input("Enter case-sensitive name of service.\n")
            cur.execute("SELECT pw FROM logs WHERE id = '" + to_pull + "'")
            rows = cur.fetchall()
            
            print("Your password is: " + password_decrypt(rows[0][0], userpass).decode())
            
        
        elif (selection == '4'):
            quit()
    
        else:
            print("Invalid input.\n")
    
    
    
    
    
