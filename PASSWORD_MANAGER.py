import tkinter as tk
from tkinter import messagebox, simpledialog
from cryptography.fernet import Fernet
import sqlite3
import string
import random
import cryptography.fernet

# Database setup
conn = sqlite3.connect('password_manager.db')
cursor = conn.cursor()

# Generate a key for encryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Flag to track if the notification has been shown
notification_shown = False


def create_table():
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()


def encrypt_password(password):
    return cipher_suite.encrypt(password.encode()).decode()


def decrypt_password(encrypted_password):
    try:
        return cipher_suite.decrypt(encrypted_password.encode()).decode()
    except cryptography.fernet.InvalidToken:
        messagebox.showerror("Error", "Invalid password. Unable to decrypt.")
        return ""


def add_user(username, password):
    global notification_shown  # Use the global variable

    try:
        strength = password_manager_app.check_password_strength(password)
        if strength == "Strong":
            encrypted_password = encrypt_password(password)
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, encrypted_password))
            conn.commit()

            # Check if the notification has already been shown
            if not notification_shown:
                messagebox.showinfo("Success", "User added successfully.")
                notification_shown = True  # Set the flag to True after showing the notification
        else:
            messagebox.showwarning("Error", "Password strength is not strong. Please choose a stronger password.")
    except sqlite3.IntegrityError:
        messagebox.showwarning("Error", "Username already exists. Please choose a different username.")


class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")

        # Set background color to light black
        self.root.configure(bg="#1f1f1f")

        create_table()

        # Username and Password Entry
        self.username_label = tk.Label(root, text="Username:", bg="#1f1f1f", fg="white", font=("Sitka Banner", 12))
        self.username_label.grid(row=0, column=0, pady=5, padx=5)
        self.username_entry = tk.Entry(root, bg="lightgrey", fg="black", font=("Sitka Banner", 12))
        self.username_entry.grid(row=0, column=1, pady=5, padx=5)

        self.password_label = tk.Label(root, text="Password:", bg="#1f1f1f", fg="white", font=("Sitka Banner", 12))
        self.password_label.grid(row=1, column=0, pady=5, padx=5)
        self.password_entry = tk.Entry(root, show="*", bg="lightgrey", fg="black", font=("Sitka Banner", 12))
        self.password_entry.grid(row=1, column=1, pady=5, padx=5)
        self.password_entry.bind("<KeyRelease>", self.on_password_change)

        # Password Strength Indicator
        self.strength_label = tk.Label(root, text="Password Strength:", bg="#1f1f1f", fg="white", font=("Sitka Banner", 12))
        self.strength_label.grid(row=2, column=0, pady=5, padx=5)
        self.strength_var = tk.StringVar()
        self.strength_var.set("Weak")
        self.strength_display = tk.Label(root, textvariable=self.strength_var, fg="red", bg="#1f1f1f", font=("Sitka Banner", 12))
        self.strength_display.grid(row=2, column=1, pady=5, padx=5)

        # Buttons
        self.add_button = tk.Button(root, text="Add User", command=self.add_user, bg="#00ff00", fg="black", font=("Sitka Banner", 12))
        self.add_button.grid(row=3, column=0, columnspan=2, pady=10, padx=5)

        self.generate_password_button = tk.Button(root, text="Generate Password", command=self.generate_password, bg="#00ff00", fg="black", font=("Sitka Banner", 12))
        self.generate_password_button.grid(row=4, column=0, columnspan=2, pady=10, padx=5)

        self.retrieve_button = tk.Button(root, text="Retrieve Usernames/Passwords", command=self.retrieve_usernames_passwords, bg="#00ff00", fg="black", font=("Sitka Banner", 12))
        self.retrieve_button.grid(row=5, column=0, columnspan=2, pady=10, padx=5)

    def add_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if username and password:
            strength = self.check_password_strength(password)
            if strength == "Strong":
                add_user(username, password)
            else:
                messagebox.showwarning("Error", "Password strength is not strong. Please choose a stronger password.")
        else:
            messagebox.showwarning("Error", "Username and password are required.")

    def generate_password(self):
        length = 12
        suggested_password = self.generate_strong_password(length)

        result = messagebox.askquestion("Suggested Password", f"Suggested Password: {suggested_password}\n\nUse this password?")
        if result == 'yes':
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, suggested_password)
            self.on_password_change()  # Trigger password change event to update strength

    def check_password_strength(self, password):
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in string.punctuation for c in password)

        if len(password) >= 8 and has_upper and has_lower and has_digit and has_symbol:
            return "Strong"
        elif len(password) >= 6:
            return "Moderate"
        else:
            return "Weak"

    def on_password_change(self, *_):
        password = self.password_entry.get()
        strength = self.check_password_strength(password)
        self.strength_var.set(strength)
        color = "green" if strength == "Strong" else "red"
        self.strength_display.config(fg=color)

    def generate_strong_password(self, length=12):
        chars = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(chars) for _ in range(length))
        return password

    def retrieve_usernames_passwords(self):
        # Prompt user for credentials
        input_username = simpledialog.askstring("Input", "Enter your username:")
        input_password = simpledialog.askstring("Input", "Enter your password:", show="*")

        if not (input_username and input_password):
            messagebox.showwarning("Error", "Username and password are required.")
            return

        cursor.execute("SELECT username, password FROM users WHERE username = ?", (input_username,))
        row = cursor.fetchone()

        if row:
            decrypted_password = decrypt_password(row[1])
            if decrypted_password:  # Check if the password is not empty
                if input_password == decrypted_password:
                    messagebox.showinfo("Success", f"Username: {input_username}\nPassword: {decrypted_password}")
                else:
                    messagebox.showwarning("Error", "Incorrect password.")
            else:
                # Password decryption failed, show error message
                messagebox.showerror("Error", "Unable to retrieve password.")
        else:
            messagebox.showwarning("Error", "Username not found.")


if __name__ == "__main__":
    app_root = tk.Tk()
    password_manager_app = PasswordManagerApp(app_root)
    app_root.mainloop()

    conn.close()
