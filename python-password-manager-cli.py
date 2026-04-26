import sqlite3
import bcrypt
import time


conn = sqlite3.connect("PWMANEGER.db") # Verbindung zur Datenbank herstellen oder die Datenbank erstellen, wenn sie nicht existiert 
cursor = conn.cursor() #Die Eigentliche SQL-Befehle werden über "Cursor" ausgeführt
cursor.execute("""  
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash BLOB,
    rolle TEXT
)
""")
#Erstellung eines "Starter-Admin" Benutzers weil die Datenbank anfangs leer ist.
cursor.execute("SELECT * FROM users WHERE username = ?", ("admin",))
if cursor.fetchone() is None:
    password = "admin123"
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()) #Passwort wird gehasht, damit es nicht im Klartext in der Datenbank gespeichert wird. bcrypt ist eine sichere Hashing-Funktion, die speziell für Passwörter entwickelt wurde.

    cursor.execute("""
        INSERT INTO users (username, password_hash, rolle)
        VALUES (?, ?, ?)
    """, ("admin", sqlite3.Binary(hashed), "admin"))

    conn.commit()
    print("Default Admin erstellt: admin / admin123")


conn.commit()

####### Funktionen #######
#Nutzer erstellen, Nutzer auflisten, Nutzer löschen, Login, Menü anzeigen, Bildschirm löschen

#Nutzer erstellen: Admins können neue Nutzer anlegen, indem sie einen Benutzernamen, ein Passwort und eine Rolle (admin/user) eingeben.
def create_user(): 
    username = input("Nutzername eingeben: ")
    hashed_password = input("Passwort eingeben: ")
    rolle = input("Rolle eingeben (admin/user): ").lower()

    if rolle not in ["admin", "user"]:
        print("Ungültige Rolle! Bitte 'admin' oder 'user' eingeben.")
        rolle = "user"
    
    cursor.execute("SELECT * FROM users WHERE username = ?",(username,))
    if cursor.fetchone():
        print("User existiert bereits!")
        input("Drücke Enter zum Fortfahren...")
        return
    
    hashed_password = bcrypt.hashpw(hashed_password.encode('utf-8'), bcrypt.gensalt())

    cursor.execute("INSERT INTO users (username, password_hash, rolle) VALUES (?, ?, ?)",(username, sqlite3.Binary(hashed_password), rolle))
    conn.commit()
    print("User erstellt!")
    input("Drücke Enter zum Fortfahren...")


#Nutzer auflisten: Admins können alle vorhandenen Nutzer und deren Rollen anzeigen lassen.
def list_users():
    cursor.execute("SELECT username, rolle FROM users")
    rows = cursor.fetchall()
    for row in rows:
        print(f"Nutzername: {row[0]}, Rolle: {row[1]}")
    
    input("Drücke Enter zum Fortfahren...")

#Nutzer löschen: Admins können Nutzer entfernen, indem sie den Benutzernamen eingeben. 
def delete_user():
    username = input("Nutzer eingeben: ")
    cursor.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    if cursor.rowcount == 0:
        print("Nutzer nicht gefunden!")
    else:
        print("Nutzer gelöscht!")
    input("Drücke Enter zum Fortfahren...")

#Login: Nutzer können sich mit ihrem Benutzernamen und Passwort anmelden.
def login():
    username = input("Nutzername eingeben: ")
    password = input("Passwort eingeben: ")
    cursor.execute("SELECT password_hash,rolle FROM users WHERE username = ?", (username,)) # Gibt es diesen Nutzer überhaupt? Wenn ja, wird der Passwort-Hash und die Rolle zurückgegeben.
    row = cursor.fetchone()

    if row is None:
        print("Anmeldung fehlgeschlagen!")
        input("Drücke Enter zum Fortfahren...")
        return None
    
    stored_password_hash = row[0]
    rolle = row[1]

    if isinstance(stored_password_hash, memoryview):
        stored_password_hash = stored_password_hash.tobytes()

    if bcrypt.checkpw(password.encode('utf-8'), stored_password_hash):
        print("Login erfolgreich!")
        input("Drücke Enter zum Fortfahren...")
        return username,rolle
    else:
        print("Anmeldung fehlgeschlagen!")
        input("Drücke Enter zum Fortfahren...")
        return None


def clearscreen():    
    print("\033[H\033[J", end="")

def menu(current_user):
    print("---------------Passwort Manager---------------")

    if current_user:
        print(f"Angemeldet als: {current_user[0]} ({current_user[1]})")
    else:
        print("Nicht angemeldet")
    print("1 Login")
    if current_user and current_user[1] == "admin":
        print("2 Nutzer erstellen")
        print("3 Nutzer auflisten")
        print("4 Nutzer löschen")
    print("5 Abmelden")
    print("6 Beenden")
    
    return input("\nWähle eine Option: ")

current_user = None

while True:
    clearscreen()
    choice = menu(current_user)
    if choice == "1":
        user = login()
        if user:
            current_user = user
    elif choice == "2":
        if current_user and current_user[1] == "admin":
            create_user()
        else:
            print("Zugriff verweigert! Nur Admins können Nutzer erstellen.")
            input("Drücke Enter zum Fortfahren...")
    elif choice == "3":
        if current_user and current_user[1] == "admin":
            list_users()
        else:
            print("Zugriff verweigert! Nur Admins können Nutzer auflisten.")
            input("Drücke Enter zum Fortfahren...")
    elif choice == "4":
        if current_user and current_user[1] == "admin":
            delete_user()
        else:
            print("Zugriff verweigert! Nur Admins können Nutzer löschen.")
            input("Drücke Enter zum Fortfahren...")
    elif choice == "5":
        current_user = None
        print("Ausgeloggt!")
        input("Drücke Enter zum Fortfahren...")
    elif choice == "6":
        break

conn.close()