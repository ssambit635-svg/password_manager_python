import json
import os
import hashlib
import getpass
import random
import string
from cryptography.fernet import Fernet
import base64

# ── File where passwords will be saved ──
DATA_FILE = "passwords.json"
MASTER_FILE = "master.json"


# ══════════════════════════════════════
#  MASTER PASSWORD
# ══════════════════════════════════════

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
# ══════════════════════════════════════
#  ENCRYPTION & DECRYPTION
# ══════════════════════════════════════

def generate_key(master_password):
    """Turn master password into an encryption key."""
    key = base64.urlsafe_b64encode(
        hashlib.sha256(master_password.encode()).digest()
    )
    return Fernet(key)


def encrypt_data(data, fernet):
    """Lock the data — turn readable text into gibberish."""
    text = json.dumps(data)
    return fernet.encrypt(text.encode()).decode()


def decrypt_data(encrypted_text, fernet):
    """Unlock the data — turn gibberish back to readable."""
    decrypted = fernet.decrypt(encrypted_text.encode())
    return json.loads(decrypted)


def set_master_password():
    print("\n🔐 Set your Master Password")
    pwd = getpass.getpass("Enter master password: ")
    confirm = getpass.getpass("Confirm master password: ")

    if pwd != confirm:
        print("❌ Passwords do not match!")
        return

    with open(MASTER_FILE, "w") as f:
        json.dump({"master": hash_password(pwd)}, f)
    print("✅ Master password set successfully!")


def verify_master_password():
    if not os.path.exists(MASTER_FILE):
        print("⚠️  No master password found. Let's set one up first.")
        set_master_password()
        return None

    pwd = getpass.getpass("\n🔑 Enter Master Password: ")
    with open(MASTER_FILE, "r") as f:
        data = json.load(f)

    if hash_password(pwd) == data["master"]:
        print("✅ Access granted!")
        return pwd          # 👈 now RETURNS the password instead of True
    else:
        print("❌ Wrong password! Access denied.")
        return None         # 👈 returns None instead of False

# ══════════════════════════════════════
#  ADD PASSWORD
# ══════════════════════════════════════

def add_password(fernet):
    print("\n➕ Add New Password")
    site = input("Website/App name (e.g. Facebook): ")
    username = input("Username or Email: ")
    password = getpass.getpass("Password: ")

    # Load and decrypt existing data
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            encrypted = f.read()
        data = decrypt_data(encrypted, fernet)
    else:
        data = []

    data.append({
        "site": site,
        "username": username,
        "password": password
    })

    # Encrypt and save
    with open(DATA_FILE, "w") as f:
        f.write(encrypt_data(data, fernet))

    print(f"✅ Password for '{site}' saved & encrypted!")


def view_passwords(fernet):
    print("\n📋 All Saved Passwords")

    if not os.path.exists(DATA_FILE):
        print("⚠️  No passwords saved yet.")
        return

    with open(DATA_FILE, "r") as f:
        encrypted = f.read()

    data = decrypt_data(encrypted, fernet)

    if len(data) == 0:
        print("⚠️  Your vault is empty.")
        return

    for i, entry in enumerate(data, start=1):
        print(f"\n{i}. 🌐 Site     : {entry['site']}")
        print(f"   👤 Username : {entry['username']}")
        print(f"   🔑 Password : {entry['password']}")


def search_password(fernet):
    print("\n🔍 Search Password")
    keyword = input("Enter website/app name to search: ").lower()

    if not os.path.exists(DATA_FILE):
        print("⚠️  No passwords saved yet.")
        return

    with open(DATA_FILE, "r") as f:
        encrypted = f.read()

    data = decrypt_data(encrypted, fernet)
    results = [entry for entry in data if keyword in entry["site"].lower()]

    if len(results) == 0:
        print(f"❌ No results found for '{keyword}'")
        return

    print(f"\n✅ Found {len(results)} result(s):\n")
    for i, entry in enumerate(results, start=1):
        print(f"{i}. 🌐 Site     : {entry['site']}")
        print(f"   👤 Username : {entry['username']}")
        print(f"   🔑 Password : {entry['password']}\n")


def delete_password(fernet):
    print("\n🗑️  Delete a Password")

    if not os.path.exists(DATA_FILE):
        print("⚠️  No passwords saved yet.")
        return

    with open(DATA_FILE, "r") as f:
        encrypted = f.read()

    data = decrypt_data(encrypted, fernet)

    if len(data) == 0:
        print("⚠️  Your vault is empty.")
        return

    for i, entry in enumerate(data, start=1):
        print(f"{i}. {entry['site']} — {entry['username']}")

    try:
        choice = int(input("\nEnter the number to delete: "))
        if choice < 1 or choice > len(data):
            print("⚠️  Invalid number.")
            return
    except ValueError:
        print("⚠️  Please enter a valid number.")
        return

    removed = data.pop(choice - 1)
    confirm = input(f"⚠️  Are you sure you want to delete '{removed['site']}'? (yes/no): ")

    if confirm.lower() == "yes":
        with open(DATA_FILE, "w") as f:
            f.write(encrypt_data(data, fernet))
        print(f"✅ '{removed['site']}' deleted successfully!")
    else:
        print("↩️  Deletion cancelled. Nothing was removed.")


def generate_password(fernet):
    print("\n🎲 Random Password Generator")

    try:
        length = int(input("How many characters? (recommended: 12-16): "))
        if length < 6:
            print("⚠️  Too short! Minimum is 6 characters.")
            return
    except ValueError:
        print("⚠️  Please enter a valid number.")
        return

    print("\nWhat to include?")
    use_upper = input("Uppercase letters? A-Z (yes/no): ").lower() == "yes"
    use_digits = input("Numbers? 0-9 (yes/no): ").lower() == "yes"
    use_symbols = input("Symbols? !@#$% (yes/no): ").lower() == "yes"

    chars = string.ascii_lowercase
    if use_upper:
        chars += string.ascii_uppercase
    if use_digits:
        chars += string.digits
    if use_symbols:
        chars += string.punctuation

    password = "".join(random.choice(chars) for _ in range(length))
    print(f"\n✅ Your generated password: {password}")

    save = input("\nWant to save this password? (yes/no): ").lower()
    if save == "yes":
        site = input("Website/App name: ")
        username = input("Username or Email: ")

        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, "r") as f:
                encrypted = f.read()
            data = decrypt_data(encrypted, fernet)
        else:
            data = []

        data.append({
            "site": site,
            "username": username,
            "password": password
        })

        with open(DATA_FILE, "w") as f:
            f.write(encrypt_data(data, fernet))

        print(f"✅ Saved & encrypted password for '{site}'!")
    else:
        print("👍 Okay! Make sure you copy it somewhere safe.")


# ══════════════════════════════════════
#  VIEW PASSWORDS
# ══════════════════════════════════════

def view_passwords():
    print("\n📋 All Saved Passwords")

    if not os.path.exists(DATA_FILE):
        print("⚠️  No passwords saved yet.")
        return

    with open(DATA_FILE, "r") as f:
        data = json.load(f)

    if len(data) == 0:
        print("⚠️  Your vault is empty.")
        return

    for i, entry in enumerate(data, start=1):
        print(f"\n{i}. 🌐 Site     : {entry['site']}")
        print(f"   👤 Username : {entry['username']}")
        print(f"   🔑 Password : {entry['password']}")


# ══════════════════════════════════════
#  SEARCH PASSWORD
# ══════════════════════════════════════

def search_password():
    print("\n🔍 Search Password")
    keyword = input("Enter website/app name to search: ").lower()

    if not os.path.exists(DATA_FILE):
        print("⚠️  No passwords saved yet.")
        return

    with open(DATA_FILE, "r") as f:
        data = json.load(f)

    results = [entry for entry in data if keyword in entry["site"].lower()]

    if len(results) == 0:
        print(f"❌ No results found for '{keyword}'")
        return

    print(f"\n✅ Found {len(results)} result(s):\n")
    for i, entry in enumerate(results, start=1):
        print(f"{i}. 🌐 Site     : {entry['site']}")
        print(f"   👤 Username : {entry['username']}")
        print(f"   🔑 Password : {entry['password']}\n")


# ══════════════════════════════════════
#  DELETE PASSWORD
# ══════════════════════════════════════

def delete_password():
    print("\n🗑️  Delete a Password")

    if not os.path.exists(DATA_FILE):
        print("⚠️  No passwords saved yet.")
        return

    with open(DATA_FILE, "r") as f:
        data = json.load(f)

    if len(data) == 0:
        print("⚠️  Your vault is empty.")
        return

    for i, entry in enumerate(data, start=1):
        print(f"{i}. {entry['site']} — {entry['username']}")

    try:
        choice = int(input("\nEnter the number to delete: "))
        if choice < 1 or choice > len(data):
            print("⚠️  Invalid number.")
            return
    except ValueError:
        print("⚠️  Please enter a valid number.")
        return

    removed = data.pop(choice - 1)
    confirm = input(f"⚠️  Are you sure you want to delete '{removed['site']}'? (yes/no): ")

    if confirm.lower() == "yes":
        with open(DATA_FILE, "w") as f:
            json.dump(data, f, indent=4)
        print(f"✅ '{removed['site']}' deleted successfully!")
    else:
        print("↩️  Deletion cancelled. Nothing was removed.")


# ══════════════════════════════════════
#  RANDOM PASSWORD GENERATOR
# ══════════════════════════════════════

def generate_password():
    print("\n🎲 Random Password Generator")

    try:
        length = int(input("How many characters? (recommended: 12-16): "))
        if length < 6:
            print("⚠️  Too short! Minimum is 6 characters.")
            return
    except ValueError:
        print("⚠️  Please enter a valid number.")
        return

    print("\nWhat to include?")
    use_upper = input("Uppercase letters? A-Z (yes/no): ").lower() == "yes"
    use_digits = input("Numbers? 0-9 (yes/no): ").lower() == "yes"
    use_symbols = input("Symbols? !@#$% (yes/no): ").lower() == "yes"

    chars = string.ascii_lowercase

    if use_upper:
        chars += string.ascii_uppercase
    if use_digits:
        chars += string.digits
    if use_symbols:
        chars += string.punctuation

    password = "".join(random.choice(chars) for _ in range(length))

    print(f"\n✅ Your generated password: {password}")

    save = input("\nWant to save this password? (yes/no): ").lower()
    if save == "yes":
        site = input("Website/App name: ")
        username = input("Username or Email: ")

        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, "r") as f:
                data = json.load(f)
        else:
            data = []

        data.append({
            "site": site,
            "username": username,
            "password": password
        })

        with open(DATA_FILE, "w") as f:
            json.dump(data, f, indent=4)

        print(f"✅ Saved password for '{site}'!")
    else:
        print("👍 Okay! Make sure you copy it somewhere safe.")


# ══════════════════════════════════════
#  PASSWORD STRENGTH CHECKER
# ══════════════════════════════════════

def check_password_strength():
    print("\n💪 Password Strength Checker")
    password = getpass.getpass("Enter password to check: ")

    score = 0
    feedback = []

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("❌ Too short! Use at least 8 characters.")

    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("❌ Add uppercase letters (A-Z)")

    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("❌ Add lowercase letters (a-z)")

    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("❌ Add some numbers (0-9)")

    if any(c in string.punctuation for c in password):
        score += 2
    else:
        feedback.append("❌ Add symbols like !@#$%")

    print("\n📊 Result:")
    if score >= 6:
        print("🟢 STRONG password! Great job.")
    elif score >= 4:
        print("🟡 MEDIUM password. Could be better.")
    else:
        print("🔴 WEAK password! Please improve it.")

    print(f"🔢 Score: {score}/7")

    if feedback:
        print("\n💡 Tips to improve:")
        for tip in feedback:
            print(f"   {tip}")


# ══════════════════════════════════════
#  MAIN — Entry Point
# ══════════════════════════════════════

if __name__ == "__main__":
    master_pwd = verify_master_password()
    if not master_pwd:
        exit()

    fernet = generate_key(master_pwd)   # 👈 create the lock/unlock tool
    del master_pwd                       # 👈 forget the password immediately for safety

    print("\n🎉 Welcome to your Password Manager!")

    while True:
        print("\n─────────────────────────")
        print("1. ➕ Add Password")
        print("2. 📋 View Passwords")
        print("3. 🔍 Search Password")
        print("4. 🗑️  Delete Password")
        print("5. 🎲 Generate Password")
        print("6. 💪 Check Password Strength")
        print("7. ❌ Exit")
        print("─────────────────────────")

        choice = input("Choose an option (1-7): ")

        if choice == "1":
            add_password(fernet)
        elif choice == "2":
            view_passwords(fernet)
        elif choice == "3":
            search_password(fernet)
        elif choice == "4":
            delete_password(fernet)
        elif choice == "5":
            generate_password(fernet)
        elif choice == "6":
            check_password_strength()
        elif choice == "7":
            print("\n👋 Goodbye! Stay safe.")
            break
        else:
            print("⚠️  Invalid choice. Try again.")
            