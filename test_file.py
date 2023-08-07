import glob
import logging
import tempfile
import tkinter
import tkinter as tk
from tkinter import messagebox
import customtkinter
import sqlite3
import os
import binascii
import argon2
import time
import random
import string
import pyperclip
from CTkMessagebox import CTkMessagebox
import re
from PIL import ImageColor
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import ctypes
import base64



customtkinter.set_appearance_mode("System")  # Modes: system (default), light, dark
customtkinter.set_default_color_theme("blue")  # Themes: blue (default), dark-blue, green

app = customtkinter.CTk()
ENCRYPTION_KEY = None
selected_search_row = []
selected_search_entries = []
filtered_data = []

# database here
with sqlite3.connect("reqwrqew.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
username TEXT NOT NULL,
salt TEXT NOT NULL,
password TEXT NOT NULL);
""")


def generate_salt():
    # generate a random salt value
    salt = os.urandom(16)
    return binascii.hexlify(salt).decode("utf-8")


def hash_password(password, salt):
    # hashing the password the salt using a secure algorithm
    argon2_hasher = argon2.PasswordHasher()
    hashed_password = argon2_hasher.hash(password + salt)
    return hashed_password


def first_time_login():
    screen_width = app.winfo_screenwidth()
    screen_height = app.winfo_screenheight()
    window_width = 600
    window_height = 350

    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2
    app.geometry(f"{window_width}x{window_height}+{x}+{y}")
    app.minsize(600, 370)
    app.maxsize(600, 370)
    app.title("VaultBuddy")

    def update_password_requirements(password_first, password_first2, password_requirements_labels):
        password = password_first.get()
        password2 = password_first2.get()

        requirements = [
            r".{8,}", r"[a-z]", r"[A-Z]", r"\d", r"[@$!%*?&]"
        ]

        set_label_color = lambda labels, meets_req: [label.configure(text_color=("green" if meets_req else "red")) for label in
                                                     labels]

        set_label_color(password_requirements_labels[:5], False)
        set_label_color(password_requirements_labels[5:], False)

        for i, req in enumerate(requirements):
            meets_req_pass1 = bool(re.search(req, password))
            meets_req_pass2 = bool(re.search(req, password2))
            set_label_color(password_requirements_labels[i:i + 5], meets_req_pass1)
            set_label_color(password_requirements_labels[i + 5:i + 10], meets_req_pass2)

        passwords_match = password == password2
        set_label_color(password_requirements_labels[-1:], passwords_match)

    def toggle_password_visibility():
        if password_first.cget("show") == "*":
            password_first.configure(show="")
            password_first2.configure(show="")
            toggle_password_button.configure(text="Hide Password")
        else:
            password_first.configure(show="*")
            password_first2.configure(show="*")
            toggle_password_button.configure(text="Show Password")

    label = customtkinter.CTkLabel(app, text="Create Credential", font=customtkinter.CTkFont(size=18))
    label.place(relx=0.5, rely=0.1, anchor=customtkinter.CENTER)

    username_first_label = customtkinter.CTkLabel(app, text="Enter your Username:", font=customtkinter.CTkFont(size=15))
    username_first_label.place(relx=0.02, rely=0.3, anchor='w')

    username_first = customtkinter.CTkEntry(app, width=280, font=customtkinter.CTkFont(size=15))
    username_first.place(relx=0.5, rely=0.3, anchor=customtkinter.CENTER)

    label1 = customtkinter.CTkLabel(app, text="Create password:      ", font=customtkinter.CTkFont(size=15))
    label1.place(relx=0.02, rely=0.4, anchor='w')

    password_first = customtkinter.CTkEntry(app, width=280, show="*")
    password_first.place(relx=0.5, rely=0.4, anchor=customtkinter.CENTER)

    label2 = customtkinter.CTkLabel(app, text="Re-enter password:", font=customtkinter.CTkFont(size=15))
    label2.place(relx=0.02, rely=0.5, anchor='w')

    password_first2 = customtkinter.CTkEntry(app, width=280, show="*")
    password_first2.place(relx=0.5, rely=0.5, anchor=customtkinter.CENTER)
    toggle_password_button = customtkinter.CTkButton(app, text="Show Password", command=toggle_password_visibility,
                                                     font=customtkinter.CTkFont(size=12, weight="normal"), width=40)
    toggle_password_button.place(relx=0.85, rely=0.45, anchor=customtkinter.CENTER)

    password_requirements_labels = []

    requirements = (
        "1. At least 8 characters in length",
        "2. Contains at least one lowercase letter",
        "3. Contains at least one uppercase letter",
        "4. Contains at least one digit",
        "5. Contains at least one special character (@,$,!,%,*,?,&)",
        "6. Password match"
    )

    for i, requirement_text in enumerate(requirements):
        label = customtkinter.CTkLabel(app, text=requirement_text, font=customtkinter.CTkFont(size=12))
        label.place(relx=0.5, rely=0.69 + i * 0.055, anchor=customtkinter.CENTER)
        password_requirements_labels.append(label)

    label_error = customtkinter.CTkLabel(app, text="")
    label_error.place(relx=0.5, rely=0.58, anchor=customtkinter.CENTER)

    event_handler = lambda event: update_password_requirements(password_first, password_first2,
                                                               password_requirements_labels)
    password_first.bind("<Key>", event_handler)
    password_first2.bind("<Key>", event_handler)
    password_first.bind("<KeyRelease>", event_handler)
    password_first2.bind("<KeyRelease>", event_handler)

    def save_account():
        if username_first.get() and password_first.get and password_first2:
            if password_first.get() == password_first2.get():
                # Check the password strength
                if is_strong_password(password_first.get()):
                    salt = generate_salt()
                    hashed_password = hash_password(password_first.get(), salt)

                    insert_account = """INSERT INTO masterpassword(username, salt ,password) VALUES(?, ?, ?) """
                    cursor.execute(insert_account, [(username_first.get()), (salt), (hashed_password)])
                    db.commit()

                    password_main()
                else:
                    CTkMessagebox(app, title="Error", message="Passwords need to meet the requirement of password policy", icon="warning")
            else:
                CTkMessagebox(app, title="Error", message="Passwords do not match! Please re-enter again", icon="warning")
        else:
            CTkMessagebox(app, title="Error", message="Please do not leave any field empty", icon="warning")

    strong_password_pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"

    def is_strong_password(password):
        return re.match(strong_password_pattern, password) is not None

    button = customtkinter.CTkButton(app, text='Set password', command=save_account,
                                     font=customtkinter.CTkFont(size=14, weight="normal"))
    button.place(relx=0.5, rely=0.62, anchor=customtkinter.CENTER)


def real_login():
    screen_width = app.winfo_screenwidth()
    screen_height = app.winfo_screenheight()
    window_width = 600
    window_height = 350

    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2
    app.geometry(f"{window_width}x{window_height}+{x}+{y}")
    app.minsize(600, 280)
    app.maxsize(600, 280)
    app.title("VaultBuddy")

    def toggle_password_visibility():
        if password_login.cget("show") == "*":
            password_login.configure(show="")
            toggle_password_button.configure(text="Hide Password")
        else:
            password_login.configure(show="*")
            toggle_password_button.configure(text="Show Password")

    label = customtkinter.CTkLabel(app, text="Login Screen", font=("Arial", 35))
    label.place(relx=0.5, rely=0.15, anchor=customtkinter.CENTER)

    username_label = customtkinter.CTkLabel(app, text="Enter username:", font=customtkinter.CTkFont(size=15))
    username_label.place(relx=0.15, rely=0.35, anchor=customtkinter.CENTER)

    username_login = customtkinter.CTkEntry(app, width=280, height=28, font=customtkinter.CTkFont(size=15))
    username_login.place(relx=0.5, rely=0.35, anchor=customtkinter.CENTER)

    label1 = customtkinter.CTkLabel(app, text="Enter master key:", font=customtkinter.CTkFont(size=15))
    label1.place(relx=0.15, rely=0.55, anchor=customtkinter.CENTER)

    password_login = customtkinter.CTkEntry(app, width=280, height=28, show="*")
    password_login.place(relx=0.5, rely=0.55, anchor=customtkinter.CENTER)

    toggle_password_button = customtkinter.CTkButton(app, width=40, text="Show Password", font=customtkinter.CTkFont(size=12), command=toggle_password_visibility)
    toggle_password_button.place(relx=0.83, rely=0.55, anchor=customtkinter.CENTER)

    max_attempts = 5
    login_attempts = 1
    timer_active = False
    timer_duration = 30  # seconds

    def start_timer():
        nonlocal timer_active
        timer_active = True
        end_time = time.time() + timer_duration

        while time.time() < end_time:
            remaining_time = int(end_time - time.time())
            label_error.configure(text=f"You have reached the maximum login attempts. Retry in {remaining_time}s")
            app.update()
            button.configure(state="disabled")

        timer_active = False
        label_error.configure(text="")
        button.configure(state="normal")

    def get_master_account():

        cursor.execute("SELECT salt, password FROM masterpassword WHERE id = 1 AND username = ?",
                       [(username_login.get())])
        return cursor.fetchone()

    def check_password():
        nonlocal login_attempts

        if login_attempts >= max_attempts:
            if not timer_active:
                start_timer()
                login_attempts = 1
            return

        login_attempts += 1

        account = get_master_account()

        if account:
            stored_salt, stored_password = account
            argon2_hasher = argon2.PasswordHasher()

            try:
                argon2_hasher.verify(stored_password, password_login.get() + stored_salt)
                password_main()
            except argon2.exceptions.VerifyMismatchError:
                password_login.delete(0, 'end')
                username_login.delete(0, 'end')
                label_error.configure(
                    text=f'Wrong username or master key, you have {max_attempts - login_attempts + 1} login attempts left!')
        else:
            password_login.delete(0, 'end')
            username_login.delete(0, 'end')
            label_error.configure(
                text=f'Wrong username or master key, you have {max_attempts - login_attempts + 1} login attempts left!')

    button = customtkinter.CTkButton(app, text='Login', command=check_password,
                                     font=customtkinter.CTkFont(size=14, weight="normal"))
    button.place(relx=0.5, rely=0.8, anchor=customtkinter.CENTER)

    label_error = customtkinter.CTkLabel(app, text="", text_color='red')
    label_error.place(relx=0.5, rely=0.69, anchor=customtkinter.CENTER)


def password_main():
    for widget in app.winfo_children():
        widget.destroy()

    screen_width = app.winfo_screenwidth()
    screen_height = app.winfo_screenheight()
    window_width = 800
    window_height = 600

    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2
    app.minsize(800, 600)
    app.maxsize(800, 600)
    app.geometry(f"{window_width}x{window_height}+{x}+{y}")
    app.title("VaultBuddy")

    generated_passwords = []
    global encryption_key_shown
    encryption_key_shown = False


    # generate password define
    def password_generator():
        try:
            length = int(length_entry.get())
            if 100 >= length >= 12:
                include_lowercase = lowercase_var.get()
                include_uppercase = uppercase_var.get()
                include_digits = digit_var.get()
                include_symbols = specialchar_var.get()
                character_set = ""
                if include_lowercase:
                    character_set += string.ascii_lowercase
                if include_uppercase:
                    character_set += string.ascii_uppercase
                if include_digits:
                    character_set += string.digits
                if include_symbols:
                    character_set += string.punctuation

                if not character_set:
                    raise ValueError("At least one character set must be included in the password generation.")

                while True:
                    password = random.choices(character_set, k=length)
                    password = password[:100]
                    generated_password = "".join(password)
                    salt = generate_salt()
                    check_after_hash = hash_password(generated_password, salt)
                    if generated_password not in generated_passwords and not check_password(check_after_hash):
                        break

                password_generator_label5.configure(text='')
                copy_button.configure(state='normal')
                password_generator_entry.configure(state='normal')
                password_generator_entry.delete(0, "end")
                password_generator_entry.insert(0, "".join(password))
                password_generator_entry.configure(state='readonly')

            else:
                copy_button.configure(state='disabled')
                password_generator_entry.configure(state='normal')
                password_generator_entry.delete(0, "end")
                password_generator_label5.configure(text="Please enter the good number of length (12-100)")
                password_generator_entry.configure(state='readonly')
        except ValueError:
            copy_button.configure(state='disabled')
            password_generator_entry.configure(state='normal')
            password_generator_entry.delete(0, "end")
            password_generator_label5.configure(text="Please enter a valid number for the length")
            password_generator_entry.configure(state='readonly')

    def check_users_check_box():
        include_uppercase = uppercase_var.get()
        include_lowercase = lowercase_var.get()
        include_specialchar = specialchar_var.get()
        include_digit = digit_var.get()

        if not include_uppercase and not include_lowercase and not include_specialchar and not include_digit:
            password_generator_label5.configure(text='Please select at least one checkbox')
        else:
            password_generator()

    def create_database_if_not_exists():
        try:
            conn = sqlite3.connect("huh.db")
            conn.close()
        except Exception as e:
            raise ValueError("Error creating the database: " + str(e))

    create_database_if_not_exists()

    def create_password_table():
        try:
            conn = sqlite3.connect("huh.db")
            cursor = conn.cursor()
            cursor.execute("CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY, password TEXT)")
            conn.commit()
            conn.close()
        except Exception as e:
            raise ValueError("Error creating the password table: " + str(e))

    def save_password(hashed_password):
        try:
            conn = sqlite3.connect("huh.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO passwords (password) VALUES (?)", (hashed_password,))
            conn.commit()
            conn.close()
        except Exception as e:
            raise ValueError("Error saving the password: " + str(e))

    def copy_password_and_save_password():
        create_password_table()
        password = password_generator_entry.get()
        salt = generate_salt()  # Implement this function to generate a salt
        pyperclip.copy(password)
        CTkMessagebox(app, title="Copying Success", message="Password has been copy to the clipboard")
        hash_generated_password = hash_password(password, salt)  # Implement this function to hash the password securely
        save_password(hash_generated_password)

    def check_password(password):
        create_password_table()
        conn = sqlite3.connect("huh.db")
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM passwords")
        saved_passwords = [row[0] for row in cursor.fetchall()]
        conn.close()
        return password in saved_passwords

    # password checking define
    min_length = 8
    uppercase = re.compile('[A-Z]')
    lowercase = re.compile('[a-z]')
    digit = re.compile('[0-9]')
    special = re.compile(r'[!@#$%^&*()_+\-=[\]{}|\\:;"\'<>,.?/~]')

    def password_strength_check(password):
        length = False
        uppercase_letter = False
        lowercase_letter = False
        digitcheck = False
        special_character = False

        if min_length <= len(password):
            length = True

        for char in password:
            if uppercase.match(char):
                uppercase_letter = True
            elif lowercase.match(char):
                lowercase_letter = True
            elif digit.match(char):
                digitcheck = True
            elif special.match(char):
                special_character = True

        return length, uppercase_letter, lowercase_letter, digitcheck, special_character

    def update_checkboxes():
        password = password_checking_entry.get()
        strength = password_strength_check(password)

        password_checking_length_checkbutton_var.set(strength[0])
        password_checking_uppercase_checkbutton_var.set(strength[1])
        password_checking_lowercase_checkbutton_var.set(strength[2])
        password_checking_digit_checkbutton_var.set(strength[3])
        password_checking_special_checkbutton_var.set(strength[4])

    def changing_follow_entry(event):
        update_checkboxes()

    def checking_password_strength_progressbar(password):
        uppercase_letters = set(string.ascii_uppercase)
        lowercase_letters = set(string.ascii_lowercase)
        digits = set(string.digits)
        special_characters = set(string.punctuation)
        length = len(password)

        strength = 0
        lowercase_characters_count = 0
        uppercase_character_count = 0
        digits_count = 0
        special_count = 0
        length_count = 0

        for char in password:
            if char in lowercase_letters:
                lowercase_characters_count += 0.025
            elif char in uppercase_letters:
                uppercase_character_count += 0.04
            elif char in digits:
                digits_count += 0.04
            elif char in special_characters:
                special_count += 0.05

        if length > 8:
            length_count += 0.013
        if length > 9:
            length_count += 0.014
        if length > 10:
            length_count += 0.014
        if length > 11:
            length_count += 0.015
        if length > 12:
            length_count += 0.015
        if length > 13:
            length_count += 0.016
        if length > 14:
            length_count += 0.016
        if length > 15:
            length_count += 0.017
        if length > 16:
            length_count += 0.017
        if length > 17:
            length_count += 0.018
        if length > 18:
            length_count += 0.018
        if length > 19:
            length_count += 0.019
        if length > 20:
            length_count += 0.019
        if length > 21:
            length_count += 0.019
        if length > 22:
            length_count += 0.019
        if length > 23:
            length_count += 0.02 * (length - 23)


        strength += min(lowercase_characters_count, 0.9)
        strength += min(uppercase_character_count, 0.9)
        strength += min(digits_count, 0.9)
        strength += min(special_count, 0.9)
        strength += min(length_count, 0.9)

        return strength

    color_gradient = [
        {"value": 0.0, "color": "black"},
        {"value": 0.0001, "color": "red"},
        {"value": 0.3, "color": "orange"},
        {"value": 0.5, "color": "yellow"},
        {"value": 1.0, "color": "green"}
    ]

    def update_password_progressbar(event):
        password = password_checking_entry.get()
        strength = checking_password_strength_progressbar(password)
        password_checking_progressbar.set(value=strength)

        color = gradient_color(strength, color_gradient)
        # Update the progress bar color
        password_checking_progressbar.configure(progress_color=color)

    def gradient_color(value, gradient):
        for i in range(len(gradient) - 1):
            if value <= gradient[i + 1]['value']:
                start_color = gradient[i]['color']
                end_color = gradient[i + 1]['color']
                start_value = gradient[i]['value']
                end_value = gradient[i + 1]['value']
                ratio = (value - start_value) / (end_value - start_value)

                return interpolate_color(start_color, end_color, ratio)

        return gradient[-1]['color']

    def interpolate_color(start_color, end_color, ratio):
        start_rgb = ImageColor.getrgb(start_color)
        end_rgb = ImageColor.getrgb(end_color)

        interpolated_rgb = [
            int(start + (end - start) * ratio)
            for start, end in zip(start_rgb, end_rgb)
        ]

        interpolated_color = '#%02x%02x%02x' % tuple(interpolated_rgb)
        return interpolated_color

    def password_strength_comment(event):
        password = password_checking_entry.get()
        strength_thing = checking_password_strength_progressbar(password)

        if strength_thing == 0:
            password_checking_strength_comment.configure(text='Please enter password')
        if strength_thing >= 0.001:
            password_checking_strength_comment.configure(text='Your password is weak and easily guessable')
        if strength_thing >= 0.2:
            password_checking_strength_comment.configure(text='Your password is fairly simple and lacks of complexity')
        if strength_thing >= 0.3:
            password_checking_strength_comment.configure(
                text='Your password is moderately strong but could be improved')
        if strength_thing >= 0.4:
            password_checking_strength_comment.configure(text='Your password has some strength but is still vulnerable')
        if strength_thing >= 0.5:
            password_checking_strength_comment.configure(
                text='Your password is decently strong, but there is room for improvement')
        if strength_thing >= 0.6:
            password_checking_strength_comment.configure(text='Your password is good with a solid level of complexity')
        if strength_thing >= 0.7:
            password_checking_strength_comment.configure(
                text='Your password is strong and provide good level of security')
        if strength_thing >= 0.8:
            password_checking_strength_comment.configure(text='Your password is robust and highly secure')
        if strength_thing >= 0.9:
            password_checking_strength_comment.configure(
                text='Your password is extremely secure and highly recommended now')

    def taking_salt_and_decode():
        salt_entry = password_hashing_salt_entry.get()
        if len(salt_entry) >= 8:
            return binascii.hexlify(salt_entry.encode("utf-8")).decode("utf-8")
        else:
            password_hashing_error_label.configure(text="Please enter more than 8 characters in Salt")

    def password_hashing():
        password = password_hashing_entry.get()
        if len(password) >= 1:
            password_hashing_error_label.configure(text='')
            salt = taking_salt_and_decode()
            argon2_hash = argon2.PasswordHasher()
            hashed_password = argon2_hash.hash(password + salt)
            hex_hashed_password = binascii.hexlify(hashed_password.encode()).decode("utf-8")
            password_hashing_result_entry.configure(state='normal')
            password_hashing_result2_entry.configure(state='normal')
            password_hashing_result_entry.delete(0, "end")
            password_hashing_result2_entry.delete(0, "end")
            password_hashing_result_entry.insert(0, "".join(hex_hashed_password))
            password_hashing_result2_entry.insert(0, "".join(hashed_password))
            password_hashing_result_entry.configure(state='readonly')
            password_hashing_result2_entry.configure(state='readonly')
            password_hashing_fullview_button.configure(state='normal')
            password_hashing_fullview_button2.configure(state='normal')
        else:
            password_hashing_error_label.configure(text="Please enter at least 1 character in the Password entry field")

    def fullview1():
        full_hash = password_hashing_result_entry.get()
        msg = CTkMessagebox(title="The full view of the HEX form", message=full_hash, option_2="Copy", option_1="Exit",
                            width=400)
        response = msg.get()

        if response == "Copy":
            pyperclip.copy(full_hash)
            CTkMessagebox(title="Copying Success", message="Password has been copy to the clipboard", width=300)

    def fullview2():
        full_hash = password_hashing_result2_entry.get()
        msg = CTkMessagebox(title="The full view of the Encoded form", message=full_hash, option_2="Copy",
                            option_1="Exit", width=400)
        response = msg.get()

        if response == "Copy":
            pyperclip.copy(full_hash)
            CTkMessagebox(title="Copying Success", message="Password has been copy to the clipboard", width=300)

    def initialize_database():
        conn = sqlite3.connect("zxcvvczx.db")
        cursor = conn.cursor()
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY AUTOINCREMENT, website TEXT, account TEXT, password TEXT)"
        )
        conn.commit()
        conn.close()

    initialize_database()

    ENCRYPTION_KEY_FILE = "asdffdas.db"
    ENCRYPTION_KEY_SHOWN_FILE = "encryption_key_shown1.json"
    ENCRYPTION_KEY = None

    def create_encryption_key_db():
        if not os.path.exists(ENCRYPTION_KEY_FILE):
            conn = sqlite3.connect(ENCRYPTION_KEY_FILE)
            conn.close()
        else:
            pass

    create_encryption_key_db()

    def get_file_path(file_name):
        """
        Automatically determine the file path of the file.

        Parameters:
            file_name (str): The name of the file to search for.

        Returns:
            str: The full file path, or None if the file is not found.
        """
        # Get the user's home directory
        home_dir = os.path.expanduser("~")

        # Search for the file in the home directory and its subdirectories
        for root, _, files in os.walk(home_dir):
            if file_name in files:
                return os.path.join(root, file_name)

        # If the file is not found in the home directory, try searching in other common locations
        common_locations = [
            os.path.join(home_dir, "Desktop"),
            os.path.join(home_dir, "Documents"),
            os.path.join(home_dir, "Downloads"),
            os.path.join(home_dir, "Pictures"),
            os.path.join(home_dir, "Music"),
        ]

        for location in common_locations:
            file_path = os.path.join(location, file_name)
            if os.path.exists(file_path):
                return file_path

        # If the file is still not found, prompt the user for the file path
        user_input = ctypes.windll.user32.MessageBoxW(0, "File not found. Please enter the file path:",
                                                      "File Not Found", 1)
        if user_input == 1:  # If the user clicks "OK" on the MessageBox
            file_path = ctypes.windll.user32.GetOpenFileNameW(None, "Select File", "", "All Files (*.*)|*.*||")
            return file_path

        return None

    def set_file_permissions(file_path):
        try:
            # Get the absolute path of the file
            abs_file_path = os.path.abspath(file_path)

            # Set the permission to Administrators group
            os.chmod(abs_file_path, 0o700)

        except Exception as e:
            raise ValueError("Error loading/generating the encryption key: " + str(e))

    def show_encryption_key():
        global ENCRYPTION_KEY

        encryption_key_shown = False
        if os.path.exists(ENCRYPTION_KEY_SHOWN_FILE):
            with open(ENCRYPTION_KEY_SHOWN_FILE, "r") as f:
                data = json.load(f)
                encryption_key_shown = data.get("encryption_key_shown", False)

        if ENCRYPTION_KEY is None:
            ENCRYPTION_KEY = get_encryption_key_or_generate()

        if ENCRYPTION_KEY:
            password_manager_frame.grid(row=0, column=1, sticky='nsew')
            load_data()
            update_password_manager()
            update_canvas_frame_height()

        if ENCRYPTION_KEY and not encryption_key_shown:
            key_str = base64.b64encode(ENCRYPTION_KEY).decode('utf-8')
            option = CTkMessagebox(app, title="Encryption Key",
                                   message=f"Your encryption key is: {key_str}, (Please copy it because it will not appear again. And if you lost the key, the data in password manager also lost!)",
                                   option_1="I understand and copy to clipboard", icon="warning")
            option_get = option.get()

            if option_get == "I understand and copy to clipboard":
                key_copy = key_str
                pyperclip.copy(key_copy)
                save_encryption_key(ENCRYPTION_KEY)
                with open(ENCRYPTION_KEY_SHOWN_FILE, "w") as f:
                    json.dump({"encryption_key_shown": True}, f)
                password_manager_frame.grid(row=0, column=1, sticky='nsew')
                load_data()
                update_password_manager()
                update_canvas_frame_height()
            else:
                while True:
                    warning_option = CTkMessagebox(app, title="Warning",
                                                   message="Please make sure to copy the encryption key and keep it safe! If you lose the key, the data in the password manager will be lost.",
                                                   option_1="I understand and copy to clipboard", icon="warning")
                    warning_option_get = warning_option.get()

                    if warning_option_get == "I understand and copy to clipboard":
                        key_copy = key_str
                        pyperclip.copy(key_copy)
                        with open(ENCRYPTION_KEY_SHOWN_FILE, "w") as f:
                            json.dump({"encryption_key_shown": True}, f)
                        load_data()
                        break
                    else:
                        continue

        elif not ENCRYPTION_KEY:
            CTkMessagebox(app, title="Encryption Key",
                          message="Encryption key not found! Please create a master key first.")

    def generate_32_bytes_key():
        return get_random_bytes(32)

    def get_encryption_key_or_generate():
        encryption_key = get_encryption_key()
        if encryption_key is None:
            encryption_key = generate_32_bytes_key()
        return encryption_key

    def get_encryption_key():
        try:
            conn = sqlite3.connect(ENCRYPTION_KEY_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='encryption_key'")
            table_exists = cursor.fetchone()[0] == 1

            if not table_exists:
                conn.close()
                return None

            cursor.execute("SELECT key FROM encryption_key WHERE id = 1")
            row = cursor.fetchone()

            if row is not None:
                key = row[0]
                conn.close()
                return key
            else:
                conn.close()
                return None

        except Exception as e:
            raise ValueError("Error loading/generating the encryption key: " + str(e))

    def save_encryption_key(key):
        try:
            conn = sqlite3.connect(ENCRYPTION_KEY_FILE)
            cursor = conn.cursor()
            cursor.execute("CREATE TABLE IF NOT EXISTS encryption_key (id INTEGER PRIMARY KEY, key TEXT)")
            cursor.execute("INSERT INTO encryption_key (id, key) VALUES (1, ?)", (key,))
            conn.commit()
            conn.close()
        except Exception as e:
            raise ValueError("Error saving the encryption key: " + str(e))

    def encrypt_data(data, key):
        if isinstance(data, str):
            data = data.encode('utf-8')

        print("Before encryption:", data)  # Print the data before encryption

        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(data)

        # Combine nonce and ciphertext, and then base64 encode the result
        encrypted_data = base64.b64encode(nonce + ciphertext)

        print("Encrypted data:", encrypted_data)  # Print the encrypted data

        return encrypted_data

    def decrypt_data(encrypted_data, key):
        try:
            encrypted_data = base64.b64decode(encrypted_data)  # Decode base64-encoded encrypted data
            # Split the encrypted data into nonce and ciphertext
            nonce = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)  # Pass the correct nonce
            decrypted_data = cipher.decrypt(ciphertext)  # Decrypt the ciphertext
            return decrypted_data.decode('utf-8')
        except Exception as e:
            raise ValueError("Error decrypting the data: " + str(e))

    def save_data(data_to_save=None):
        global ENCRYPTION_KEY

        if ENCRYPTION_KEY is None:
            ENCRYPTION_KEY = get_encryption_key_or_generate()

        data_to_save = data_to_save if data_to_save is not None else data

        conn = sqlite3.connect("zxcvvczx.db")
        cursor = conn.cursor()

        cursor.execute("DELETE FROM passwords")

        for entry in data_to_save:
            website = entry["website"]
            account = entry["account"]
            password = entry["password"]

            cursor.execute("INSERT INTO passwords (website, account, password) VALUES (?, ?, ?)",
                           (website, account, password))

        conn.commit()
        conn.close()

    def load_data():
        global data

        conn = sqlite3.connect("zxcvvczx.db")
        cursor = conn.cursor()
        cursor.execute("SELECT website, account, password FROM passwords")
        rows = cursor.fetchall()
        conn.close()

        data = [{"website": website, "account": account, "password": password_base64} for
                website, account, password_base64 in rows]

        return data

    selected_row = []

    def update_password_manager():
        for widget in scroll_frame.winfo_children():
            widget.destroy()

        for row, entry in enumerate(data, start=0):
            website = entry["website"]
            account = entry["account"]

            scroll_frame.grid_columnconfigure((0, 4), weight=1, uniform='a')
            scroll_frame.grid_columnconfigure((1, 2, 3), weight=3, uniform='a')
            check_var = tkinter.IntVar()
            check_option_button = customtkinter.CTkCheckBox(scroll_frame, variable=check_var, onvalue=1, offvalue=0,
                                                            text=" ", width=30)
            check_option_button.grid(row=row, column=0, padx=10, pady=5)
            website_label = customtkinter.CTkLabel(scroll_frame, text=website,
                                                   font=customtkinter.CTkFont(size=13, weight="normal"), width=140)
            website_label.grid(row=row, column=1, sticky="nsew", padx=10, pady=5)
            account_label = customtkinter.CTkLabel(scroll_frame, text=account,
                                                   font=customtkinter.CTkFont(size=13, weight="normal"), width=140)
            account_label.grid(row=row, column=2, sticky="nsew", padx=10, pady=5)
            password_label = customtkinter.CTkLabel(scroll_frame, text="********",
                                                    font=customtkinter.CTkFont(size=13, weight="normal"), width=140)
            password_label.grid(row=row, column=3, sticky="nsew", padx=10, pady=5)
            delete_button = customtkinter.CTkButton(scroll_frame, text="...",
                                                    font=customtkinter.CTkFont(size=13, weight="normal"),
                                                    command=lambda row=row, password=entry["password"], selected_entry=entry: check_row(row, password, selected_entry),
                                                    width=50)
            delete_button.grid(row=row, column=4, sticky='nsew', padx=10, pady=5)

            selected_row.append((check_var, row))

        check_box_check()
        scroll_frame.update_idletasks()
        canvas.configure(scrollregion=canvas.bbox("all"))

        for check_var, _ in selected_row:
            check_var.trace_add("write", lambda *args: check_box_check())

    def check_box_check():
        selected_entries = [entry for check_var, entry in selected_row if check_var.get() == 1]
        if selected_entries:
            password_manager_delete_button.configure(state="normal")
        else:
            password_manager_delete_button.configure(state="disabled")

    def delete_follow_the_check():
        row_delete = [entry for check_var, entry in selected_row if check_var.get() == 1]
        row_delete.sort(reverse=True)  # to sort in descending order to avoid index shifting
        confirm = CTkMessagebox(app, title="Confirm", message="Do you really want to delete? (Can not reset)",
                                option_2="Yes", option_1="No")
        confirm_check = confirm.get()
        if confirm_check == "Yes":
            for index in row_delete:
                del data[index]

            selected_row.clear()
            save_data()
            update_password_manager()
            update_canvas_frame_height()

            password_manager_delete_button.configure(state='disabled')
        else:
            pass

        save_data()
        update_password_manager()
        update_canvas_frame_height()

        password_manager_delete_button.configure(state="disabled")

    def update_search_data(keyword):
        global selected_search_row, filtered_data

        password_manager_delete_button.configure(command=delete_follow_the_check_search)

        if keyword == "Enter keyword to search...":
            keyword = ""

        filtered_data = [entry for entry in data if
                         keyword.lower() in entry["website"].lower() or keyword.lower() in entry["account"].lower()]

        for widget in scroll_frame.winfo_children():
            widget.destroy()

        selected_search_row = []

        for row, entry in enumerate(filtered_data, start=0):
            website = entry["website"]
            account = entry["account"]

            scroll_frame.grid_columnconfigure((0, 4), weight=1, uniform='a')
            scroll_frame.grid_columnconfigure((1, 2, 3), weight=3, uniform='a')
            check_var = tkinter.IntVar()
            check_option_button = customtkinter.CTkCheckBox(scroll_frame, variable=check_var, onvalue=1, offvalue=0,
                                                            text=" ", width=30)
            check_option_button.grid(row=row, column=0, padx=10, pady=5)
            website_label = customtkinter.CTkLabel(scroll_frame, text=website,
                                                   font=customtkinter.CTkFont(size=13, weight="normal"), width=140)
            website_label.grid(row=row, column=1, sticky="nsew", padx=10, pady=5)
            account_label = customtkinter.CTkLabel(scroll_frame, text=account,
                                                   font=customtkinter.CTkFont(size=13, weight="normal"), width=140)
            account_label.grid(row=row, column=2, sticky="nsew", padx=10, pady=5)
            password_label = customtkinter.CTkLabel(scroll_frame, text="********",
                                                    font=customtkinter.CTkFont(size=13, weight="normal"), width=140)
            password_label.grid(row=row, column=3, sticky="nsew", padx=10, pady=5)
            delete_button = customtkinter.CTkButton(
                scroll_frame, text="...",
                font=customtkinter.CTkFont(size=13, weight="normal"),
                command=lambda row=row, password=entry["password"], selected_entry=entry: check_search_row(row,
                                                                                                           password,
                                                                                                           selected_entry,
                                                                                                           selected_search_row),
                width=50
            )
            delete_button.grid(row=row, column=4, sticky='nsew', padx=10, pady=5)

            selected_search_row.append((check_var, row, entry))

        check_box_check_search()
        scroll_frame.update_idletasks()
        canvas.configure(scrollregion=canvas.bbox("all"))

        for check_var, _, _ in selected_search_row:
            check_var.trace_add("write", lambda *args: check_box_check_search())

        update_canvas_frame_height_search(len(filtered_data))

    def search_key(keyword):
        global selected_search_row
        selected_search_row = [row_info[:2] for row_info in selected_search_row]
        update_search_data(keyword)

    def update_canvas_frame_height_search(num_rows):
        if num_rows > 9:
            canvas.itemconfigure(scroll_frame_window, height=False)
        else:
            canvas.itemconfigure(scroll_frame_window, height=350)

    def check_box_check_search():
        global selected_search_entries
        selected_search_entries = [entry for check_var, _, entry in selected_search_row if check_var.get() == 1]
        if selected_search_entries:
            password_manager_delete_button.configure(state="normal")
        else:
            password_manager_delete_button.configure(state="disabled")

    def delete_follow_the_check_search():
        global selected_search_row, filtered_data, data

        # Get the indices of selected rows from the filtered_data list
        rows_to_delete = [data.index(entry) for entry in selected_search_entries]

        confirm = CTkMessagebox(app, title="Confirm", message="Do you really want to delete? (Can not reset)",
                                option_2="Yes", option_1="No")
        confirm_check = confirm.get()
        if confirm_check == "Yes":
            # Delete the rows from data list
            for index in sorted(rows_to_delete, reverse=True):
                del data[index]

            # Clear the selected_search_row list
            selected_search_row.clear()

            # Update the UI with new filtered data and reset the search
            update_search_data(password_manager_find_entry.get())

            password_manager_delete_button.configure(state='disabled')
            save_data()

    def check_search_row(row, encrypted_password, selected_entry, selected_row_list):
        global ENCRYPTION_KEY

        if ENCRYPTION_KEY is None:
            CTkMessagebox(app, title="Encryption Key", message="Encryption key not found! Please reset the program.")
            return

        def on_window_close():
            child_window3.attributes("-topmost", False)
            result = CTkMessagebox(master=child_window3, title="Confirmation",
                                   message="Are you sure you want to close the window?", option_2="Yes",
                                   option_1="Cancel", icon="question").get()

            if result == "Yes":
                child_window3.destroy()
            else:
                child_window3.attributes("-topmost", True)

        def authenticate_encryption_key(user_key, row, selected_row_list):
            global selected_entry

            child_window3.attributes("-topmost", False)

            conn = sqlite3.connect(ENCRYPTION_KEY_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT key FROM encryption_key WHERE id = 1")
            stored_key = cursor.fetchone()[0]
            conn.close()
            # Convert the user-provided key to bytes
            user_key_bytes = base64.b64decode(user_key)

            def decrypt_and_fill_password(encrypted_password):
                key = user_key_bytes
                decrypted_password = decrypt_data(encrypted_password, key)
                edit_password_entry.delete(0, tkinter.END)
                edit_password_entry.insert(0, decrypted_password)

            def decrypt_and_copy(encrypted_password):
                key = user_key_bytes  # Use the same key as used for encryption
                try:
                    decrypted_password = decrypt_data(encrypted_password, key)
                    pyperclip.copy(decrypted_password)
                    CTkMessagebox(app, title="Password Copied", message="Password has been copied into clipboard!")
                    child_window3.destroy()
                    update_password_manager()
                    update_canvas_frame_height()

                except ValueError as e:
                    CTkMessagebox(app, title="Decryption Error", message="Error decrypting password: " + str(e))

            if user_key_bytes == stored_key:
                child_window3.destroy()
                selected_entry = selected_row_list[row][2]
                ask_edit = CTkMessagebox(app, title="Tasks", message="Which task do you want to do?",
                                         option_2="Copy", option_1="Delete", option_3="View and Edit",
                                         icon="question").get()

                if ask_edit == "Delete":
                    del data[row]
                    save_data(data)
                    update_password_manager()
                    update_canvas_frame_height()

                elif ask_edit == "Copy":
                    encrypted_password = data[row]["password"]
                    decrypt_and_copy(encrypted_password)

                elif ask_edit == "View and Edit":
                    def save_edited_data():
                        new_website = edit_website_entry.get()
                        new_username = edit_account_entry.get()
                        new_password = edit_password_entry.get()

                        if not new_website or not new_username or not new_password:
                            CTkMessagebox(edit_window, title="Warning",
                                          message="Please do not leave any field empty!",
                                          icon='warning')
                            return
                        else:
                            key = user_key_bytes
                            encrypted_password = encrypt_data(new_password, key)
                            selected_entry["website"] = new_website
                            selected_entry["account"] = new_username
                            selected_entry["password"] = encrypted_password

                            save_data(data)
                            load_data()
                            update_password_manager()
                            update_canvas_frame_height()
                            edit_window.destroy()

                    def on_window_close():
                        edit_window.attributes("-topmost", False)
                        result = CTkMessagebox(master=edit_window, title="Confirmation",
                                               message="Are you sure you want to close the window without save?",
                                               option_2="Yes",
                                               option_1="Cancel", icon="question").get()

                        if result == "Yes":
                            edit_window.destroy()
                        else:
                            edit_window.attributes("-topmost", True)

                    edit_window = customtkinter.CTkToplevel(app)
                    edit_screen_width = edit_window.winfo_screenwidth()
                    edit_screen_height = edit_window.winfo_screenheight()
                    edit_window_width = 500
                    edit_window_height = 300

                    x = (edit_screen_width - edit_window_width) // 2
                    y = (edit_screen_height - edit_window_height) // 2
                    edit_window.minsize(500, 300)
                    edit_window.maxsize(500, 300)
                    edit_window.geometry(f"{edit_window_width}x{edit_window_height}+{x}+{y}")
                    edit_window.title("Edit")

                    edit_label = customtkinter.CTkLabel(edit_window, text="Edit your information",
                                                        font=customtkinter.CTkFont(size=16, weight="bold"))
                    edit_label.place(relx=0.5, rely=0.1, anchor='center')
                    edit_website_label = customtkinter.CTkLabel(edit_window, text="Website:",
                                                                font=customtkinter.CTkFont(size=15,
                                                                                           weight="normal"))
                    edit_website_label.place(relx=0.05, rely=0.3, anchor='w')
                    edit_website_entry = customtkinter.CTkEntry(edit_window,
                                                                font=customtkinter.CTkFont(size=15,
                                                                                           weight="normal"),
                                                                width=400, corner_radius=10)
                    edit_website_entry.insert(0, selected_entry["website"])
                    edit_website_entry.place(relx=0.58, rely=0.3, anchor='center')
                    edit_account_label = customtkinter.CTkLabel(edit_window, text="Account:",
                                                                font=customtkinter.CTkFont(size=15,
                                                                                           weight="normal"))
                    edit_account_label.place(relx=0.05, rely=0.5, anchor='w')
                    edit_account_entry = customtkinter.CTkEntry(edit_window,
                                                                font=customtkinter.CTkFont(size=15,
                                                                                           weight="normal"),
                                                                width=400, corner_radius=10)
                    edit_account_entry.insert(0, selected_entry["account"])
                    edit_account_entry.place(relx=0.58, rely=0.5, anchor='center')
                    edit_password_label = customtkinter.CTkLabel(edit_window, text="Password:",
                                                                 font=customtkinter.CTkFont(size=15,
                                                                                            weight="normal"))
                    edit_password_label.place(relx=0.03, rely=0.7, anchor='w')
                    edit_password_entry = customtkinter.CTkEntry(edit_window,
                                                                 font=customtkinter.CTkFont(size=15,
                                                                                            weight="normal"),
                                                                 width=400, corner_radius=10)
                    edit_password_entry.place(relx=0.58, rely=0.7, anchor='center')
                    edit_password_entry.insert(0, selected_entry["password"])
                    edit_password_error = customtkinter.CTkLabel(edit_window, text="",
                                                                 font=customtkinter.CTkFont(size=13,
                                                                                            weight="normal"),
                                                                 text_color='red')
                    edit_password_error.place(relx=0.5, rely=0.8, anchor='center')
                    edit_password_button = customtkinter.CTkButton(edit_window, text='Save',
                                                                   font=customtkinter.CTkFont(size=13,
                                                                                              weight='normal'),
                                                                   command=save_edited_data)
                    edit_password_button.place(relx=0.5, rely=0.875, anchor='center')

                    encrypted_password = data[row]["password"]
                    decrypt_and_fill_password(encrypted_password)
                    edit_window.protocol("WM_DELETE_WINDOW", on_window_close)


            else:
                CTkMessagebox(app, title="Authentication Failed",
                              message="Incorrect encryption key. Action aborted!")
                child_window3.attributes("-topmost", True)

        selected_index = row

        child_window3 = customtkinter.CTkToplevel(app)
        child_screen_width = child_window3.winfo_screenwidth()
        child_screen_height = child_window3.winfo_screenheight()
        child_window_width = 500
        child_window_height = 180

        x = (child_screen_width - child_window_width) // 2
        y = (child_screen_height - child_window_height) // 2
        child_window3.minsize(500, 180)
        child_window3.maxsize(500, 180)
        child_window3.geometry(f"{child_window_width}x{child_window_height}+{x}+{y}")
        child_window3.title("Master Key check")
        child_window3.protocol("WM_DELETE_WINDOW", on_window_close)

        encryptionkey_check_mainlabel = customtkinter.CTkLabel(child_window3, text="Encryption Key Check",
                                                               font=customtkinter.CTkFont(size=20, weight="bold"))
        encryptionkey_check_mainlabel.place(relx=0.5, rely=0.1, anchor='center')

        encryptionkey_check_label = customtkinter.CTkLabel(child_window3, text="Enter your Encryption Key:",
                                                           font=customtkinter.CTkFont(size=15, weight="normal"))
        encryptionkey_check_label.place(relx=0.19, rely=0.4, anchor='center')

        encryption_key_entry = customtkinter.CTkEntry(child_window3,
                                                      font=customtkinter.CTkFont(size=15, weight="normal"), width=285,
                                                      show="*")
        encryption_key_entry.place(relx=0.665, rely=0.4, anchor='center')

        encryption_key_button = customtkinter.CTkButton(child_window3, text="Enter",
                                                        command=lambda row=row: authenticate_encryption_key(
                                                            encryption_key_entry.get(),row, selected_row_list))
        encryption_key_button.place(relx=0.5, rely=0.8, anchor='center')

        child_window3.attributes("-topmost", True)
        child_window3.wait_window()
        app.focus_set()

    def check_row(row, encrypted_password, selected_entry):
        global ENCRYPTION_KEY

        if ENCRYPTION_KEY is None:
            CTkMessagebox(app, title="Encryption Key", message="Encryption key not found! Please reset the program.")
            return

        def on_window_close():
            child_window3.attributes("-topmost", False)
            result = CTkMessagebox(master=child_window3, title="Confirmation",
                                   message="Are you sure you want to close the window?", option_2="Yes",
                                   option_1="Cancel", icon="question").get()

            if result == "Yes":
                child_window3.destroy()
            else:
                child_window3.attributes("-topmost", True)

        def authenticate_encryption_key(user_key, row):
            global selected_entry

            child_window3.attributes("-topmost", False)

            conn = sqlite3.connect(ENCRYPTION_KEY_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT key FROM encryption_key WHERE id = 1")
            stored_key = cursor.fetchone()[0]
            conn.close()
            # Convert the user-provided key to bytes
            user_key_bytes = base64.b64decode(user_key)

            def decrypt_and_fill_password(ncrypted_password):
                key = user_key_bytes
                decrypted_password = decrypt_data(encrypted_password, key)
                edit_password_entry.delete(0, tkinter.END)
                edit_password_entry.insert(0, decrypted_password)

            def decrypt_and_copy(encrypted_password):
                key = user_key_bytes  # Use the same key as used for encryption
                try:
                    decrypted_password = decrypt_data(encrypted_password, key)
                    pyperclip.copy(decrypted_password)
                    CTkMessagebox(app, title="Password Copied", message="Password has been copied into clipboard!")
                    child_window3.destroy()
                except ValueError as e:
                    CTkMessagebox(app, title="Decryption Error", message="Error decrypting password: " + str(e))

            if user_key_bytes == stored_key:
                child_window3.destroy()
                selected_entry = data[row]
                ask_edit = CTkMessagebox(app, title="Tasks", message="Which task do you want to do?",
                                         option_2="Copy", option_1="Delete", option_3="View and Edit",
                                         icon="question").get()

                if ask_edit == "Delete":
                    del data[row]
                    save_data(data)
                    update_password_manager()
                    update_canvas_frame_height()

                elif ask_edit == "Copy":
                    encrypted_password = data[row]["password"]
                    decrypt_and_copy(encrypted_password)

                elif ask_edit == "View and Edit":
                    def save_edited_data():
                        new_website = edit_website_entry.get()
                        new_username = edit_account_entry.get()
                        new_password = edit_password_entry.get()

                        if not new_website or not new_username or not new_password:
                            CTkMessagebox(edit_window, title="Warning",
                                          message="Please do not leave any field empty!",
                                          icon='warning')
                            return
                        else:
                            key = user_key_bytes
                            encrypted_password = encrypt_data(new_password, key)
                            selected_entry["website"] = new_website
                            selected_entry["account"] = new_username
                            selected_entry["password"] = encrypted_password

                            save_data(data)
                            load_data()
                            update_password_manager()
                            update_canvas_frame_height()
                            edit_window.destroy()

                    def on_window_close():
                        edit_window.attributes("-topmost", False)
                        result = CTkMessagebox(master=edit_window, title="Confirmation",
                                               message="Are you sure you want to close the window without save?",
                                               option_2="Yes",
                                               option_1="Cancel", icon="question").get()

                        if result == "Yes":
                            edit_window.destroy()
                        else:
                            edit_window.attributes("-topmost", True)

                    edit_window = customtkinter.CTkToplevel(app)
                    edit_screen_width = edit_window.winfo_screenwidth()
                    edit_screen_height = edit_window.winfo_screenheight()
                    edit_window_width = 500
                    edit_window_height = 300

                    x = (edit_screen_width - edit_window_width) // 2
                    y = (edit_screen_height - edit_window_height) // 2
                    edit_window.minsize(500, 300)
                    edit_window.maxsize(500, 300)
                    edit_window.geometry(f"{edit_window_width}x{edit_window_height}+{x}+{y}")
                    edit_window.title("Edit")

                    edit_label = customtkinter.CTkLabel(edit_window, text="Edit your information",
                                                        font=customtkinter.CTkFont(size=16, weight="bold"))
                    edit_label.place(relx=0.5, rely=0.1, anchor='center')
                    edit_website_label = customtkinter.CTkLabel(edit_window, text="Website:",
                                                                font=customtkinter.CTkFont(size=15,
                                                                                           weight="normal"))
                    edit_website_label.place(relx=0.05, rely=0.3, anchor='w')
                    edit_website_entry = customtkinter.CTkEntry(edit_window,
                                                                font=customtkinter.CTkFont(size=15,
                                                                                           weight="normal"),
                                                                width=400, corner_radius=10)
                    edit_website_entry.insert(0, selected_entry["website"])
                    edit_website_entry.place(relx=0.58, rely=0.3, anchor='center')
                    edit_account_label = customtkinter.CTkLabel(edit_window, text="Account:",
                                                                font=customtkinter.CTkFont(size=15,
                                                                                           weight="normal"))
                    edit_account_label.place(relx=0.05, rely=0.5, anchor='w')
                    edit_account_entry = customtkinter.CTkEntry(edit_window,
                                                                font=customtkinter.CTkFont(size=15,
                                                                                           weight="normal"),
                                                                width=400, corner_radius=10)
                    edit_account_entry.insert(0, selected_entry["account"])
                    edit_account_entry.place(relx=0.58, rely=0.5, anchor='center')
                    edit_password_label = customtkinter.CTkLabel(edit_window, text="Password:",
                                                                 font=customtkinter.CTkFont(size=15,
                                                                                            weight="normal"))
                    edit_password_label.place(relx=0.03, rely=0.7, anchor='w')
                    edit_password_entry = customtkinter.CTkEntry(edit_window,
                                                                 font=customtkinter.CTkFont(size=15,
                                                                                            weight="normal"),
                                                                 width=400, corner_radius=10)
                    edit_password_entry.place(relx=0.58, rely=0.7, anchor='center')
                    edit_password_entry.insert(0, selected_entry["password"])
                    edit_password_error = customtkinter.CTkLabel(edit_window, text="",
                                                                 font=customtkinter.CTkFont(size=13,
                                                                                            weight="normal"),
                                                                 text_color='red')
                    edit_password_error.place(relx=0.5, rely=0.8, anchor='center')
                    edit_password_button = customtkinter.CTkButton(edit_window, text='Save',
                                                                   font=customtkinter.CTkFont(size=13,
                                                                                              weight='normal'),
                                                                   command=save_edited_data)
                    edit_password_button.place(relx=0.5, rely=0.875, anchor='center')

                    encrypted_password = data[row]["password"]
                    decrypt_and_fill_password(encrypted_password)
                    edit_window.protocol("WM_DELETE_WINDOW", on_window_close)


            else:
                CTkMessagebox(app, title="Authentication Failed",
                              message="Incorrect encryption key. Action aborted!")
                child_window3.attributes("-topmost", True)

        selected_index = row

        child_window3 = customtkinter.CTkToplevel(app)
        child_screen_width = child_window3.winfo_screenwidth()
        child_screen_height = child_window3.winfo_screenheight()
        child_window_width = 500
        child_window_height = 180

        x = (child_screen_width - child_window_width) // 2
        y = (child_screen_height - child_window_height) // 2
        child_window3.minsize(500, 180)
        child_window3.maxsize(500, 180)
        child_window3.geometry(f"{child_window_width}x{child_window_height}+{x}+{y}")
        child_window3.title("Master Key check")
        child_window3.protocol("WM_DELETE_WINDOW", on_window_close)

        encryptionkey_check_mainlabel = customtkinter.CTkLabel(child_window3, text="Encryption Key Check",
                                                               font=customtkinter.CTkFont(size=20, weight="bold"))
        encryptionkey_check_mainlabel.place(relx=0.5, rely=0.1, anchor='center')

        encryptionkey_check_label = customtkinter.CTkLabel(child_window3, text="Enter your Encryption Key:",
                                                           font=customtkinter.CTkFont(size=15, weight="normal"))
        encryptionkey_check_label.place(relx=0.19, rely=0.4, anchor='center')

        encryption_key_entry = customtkinter.CTkEntry(child_window3,
                                                      font=customtkinter.CTkFont(size=15, weight="normal"), width=285,
                                                      show="*")
        encryption_key_entry.place(relx=0.665, rely=0.4, anchor='center')

        encryption_key_button = customtkinter.CTkButton(child_window3, text="Enter",
                                                        command=lambda row=row: authenticate_encryption_key(
                                                            encryption_key_entry.get(), row))
        encryption_key_button.place(relx=0.5, rely=0.8, anchor='center')

        child_window3.attributes("-topmost", True)
        child_window3.wait_window()
        app.focus_set()


    def insert_data():
        def submit_data():
            global ENCRYPTION_KEY

            website = website_entry.get()
            account = account_entry.get()
            password = password_entry.get()

            if not website or not account or not password:
                CTkMessagebox(master=child_window, title="Warning", message="Please fill in all the fields",
                              icon="warning")
                return
            else:
                if ENCRYPTION_KEY is None:
                    ENCRYPTION_KEY = get_encryption_key_or_generate()

                new_entry = {"website": website, "account": account, "password": encrypt_data(password, ENCRYPTION_KEY)}
                data.append(new_entry)
                save_data(data)
                update_password_manager()
                update_canvas_frame_height()
                child_window.destroy()

        child_window = customtkinter.CTkToplevel(app)
        child_screen_width = child_window.winfo_screenwidth()
        child_screen_height = child_window.winfo_screenheight()
        child_window_width = 500
        child_window_height = 300

        x = (child_screen_width - child_window_width) // 2
        y = (child_screen_height - child_window_height) // 2
        child_window.minsize(500, 300)
        child_window.maxsize(500, 300)
        child_window.geometry(f"{child_window_width}x{child_window_height}+{x}+{y}")
        child_window.title("Insert information")

        childmain_label = customtkinter.CTkLabel(child_window, text="Insert your information",
                                                 font=customtkinter.CTkFont(size=16, weight="bold"))
        childmain_label.place(relx=0.5, rely=0.1, anchor='center')
        website_label = customtkinter.CTkLabel(child_window, text="Website:",
                                               font=customtkinter.CTkFont(size=15, weight="normal"))
        website_label.place(relx=0.05, rely=0.3, anchor='w')
        website_entry = customtkinter.CTkEntry(child_window, font=customtkinter.CTkFont(size=15, weight="normal"),
                                               width=400, corner_radius=10)
        website_entry.place(relx=0.58, rely=0.3, anchor='center')
        account_label = customtkinter.CTkLabel(child_window, text="Account:",
                                               font=customtkinter.CTkFont(size=15, weight="normal"))
        account_label.place(relx=0.05, rely=0.5, anchor='w')
        account_entry = customtkinter.CTkEntry(child_window, font=customtkinter.CTkFont(size=15, weight="normal"),
                                               width=400, corner_radius=10)
        account_entry.place(relx=0.58, rely=0.5, anchor='center')
        password_label = customtkinter.CTkLabel(child_window, text="Password:",
                                                font=customtkinter.CTkFont(size=15, weight="normal"))
        password_label.place(relx=0.03, rely=0.7, anchor='w')
        password_entry = customtkinter.CTkEntry(child_window, font=customtkinter.CTkFont(size=15, weight="normal"),
                                                width=400, corner_radius=10)
        password_entry.place(relx=0.58, rely=0.7, anchor='center')
        password_error = customtkinter.CTkLabel(child_window, text="",
                                                font=customtkinter.CTkFont(size=13, weight="normal"), text_color='red')
        password_error.place(relx=0.5, rely=0.8, anchor='center')
        password_button = customtkinter.CTkButton(child_window, text='Save data',
                                                  font=customtkinter.CTkFont(size=13, weight='normal'),
                                                  command=submit_data)
        password_button.place(relx=0.5, rely=0.875, anchor='center')

        # Bring the child window to the top
        child_window.attributes("-topmost", True)
        child_window.wait_window()
        app.focus_set()

    max_attempts = 5
    login_attempts = 1
    timer_active = False
    timer_duration = 30

    def delete_database_files(*db_files):
        for db_file in db_files:
            try:
                os.remove(db_file)
                print(f"Deleted {db_file}")
            except FileNotFoundError:
                print(f"{db_file} not found. Skipping...")
            except Exception as e:
                print(f"Error deleting {db_file}: {e}")

    def delete_masterpassword_data(db_file):
        try:
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()

            cursor.execute("DELETE FROM masterpassword")

            conn.commit()
            conn.close()
            print("Master password data deleted successfully.")
        except Exception as e:
            print("Error deleting master password data:", e)

    def delete_file_shown():
        try:
            files = glob.glob("encryption_key_shown1.json")
            for file_path in files:
                os.remove(file_path)
                print(f"{file_path} deleted successfully.")
        except Exception as e:
            print("Error deleting file:", e)

    def sign_out():
        option = CTkMessagebox(app, title="Confirm", message="Do you want to sign out?", option_1="Cancel",
                               option_2="Yes")
        option_get = option.get()
        if option_get == "Yes":
            for widget in app.winfo_children():
                widget.destroy()
            real_login()
        else:
            pass

    def reset():
        option = CTkMessagebox(app, title="Confirm", message="Do you really want to reset app?", option_1="Cancel",
                               option_2="Yes")
        get_option = option.get()
        if get_option == "Yes":
            check_reset()
        else:
            pass

    def check_reset():
        def start_timer():
            nonlocal timer_active
            timer_active = True
            end_time = time.time() + timer_duration

            while time.time() < end_time:
                remaining_time = int(end_time - time.time())
                label_error.configure(text=f"You have reached the maximum login attempts. Retry in {remaining_time}s")
                app.update()
                password_key_button.configure(state="disabled")

            timer_active = False
            label_error.configure(text="")
            password_key_button.configure(state="normal")

        def get_master_account():
            cursor.execute("SELECT salt, password FROM masterpassword WHERE id = 1 AND username = ?",
                           [username_entry.get()])
            return cursor.fetchone()

        def check_password():
            nonlocal login_attempts

            if login_attempts >= max_attempts:
                if not timer_active:
                    start_timer()
                    login_attempts = 1
                return

            login_attempts += 1

            account = get_master_account()

            if account:
                stored_salt, stored_password = account
                argon2_hasher = argon2.PasswordHasher()

                try:
                    argon2_hasher.verify(stored_password, password_entry.get() + stored_salt)
                    delete_database_files("asdffdas.db", "huh.db", "zxcvvczx.db")
                    delete_masterpassword_data("reqwrqew.db")
                    delete_file_shown()
                    check_win.destroy()
                    for widget in app.winfo_children():
                        widget.destroy()
                    first_time_login()

                except argon2.exceptions.VerifyMismatchError:
                    password_entry.delete(0, 'end')
                    username_entry.delete(0, 'end')
                    label_error.configure(
                        text=f'Wrong username or master key, you have {max_attempts - login_attempts + 1} login attempts left!')
            else:
                password_entry.delete(0, 'end')
                username_entry.delete(0, 'end')
                label_error.configure(
                    text=f'Wrong username or master key, you have {max_attempts - login_attempts + 1} login attempts left!')

        check_win = customtkinter.CTkToplevel(app)
        screen_width = app.winfo_screenwidth()
        screen_height = app.winfo_screenheight()
        window_width = 600
        window_height = 200

        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        check_win.geometry(f"{window_width}x{window_height}+{x}+{y}")
        check_win.minsize(600, 200)
        check_win.maxsize(600, 200)

        password_check_mainlabel = customtkinter.CTkLabel(check_win, text="Confirm Credential",
                                                          font=customtkinter.CTkFont(size=23, weight="bold"))
        password_check_mainlabel.place(relx=0.5, rely=0.1, anchor='center')
        password_check_label = customtkinter.CTkLabel(check_win, text="Enter your Username: ",
                                                      font=customtkinter.CTkFont(size=15, weight="normal"))
        password_check_label.place(relx=0.05, rely=0.4, anchor='w')
        username_entry = customtkinter.CTkEntry(check_win, font=customtkinter.CTkFont(size=15, weight="normal"),
                                                width=285)
        username_entry.place(relx=0.6, rely=0.4, anchor='center')
        password_check_label1 = customtkinter.CTkLabel(check_win, text="Enter your Password:",
                                                       font=customtkinter.CTkFont(size=15, weight="normal"))
        password_check_label1.place(relx=0.05, rely=0.6, anchor='w')
        password_entry = customtkinter.CTkEntry(check_win,
                                                font=customtkinter.CTkFont(size=15, weight="normal"), width=285,
                                                show="*")
        password_entry.place(relx=0.6, rely=0.6, anchor='center')
        label_error = customtkinter.CTkLabel(check_win, text="",
                                             font=customtkinter.CTkFont(size=12, weight="normal"), text_color='red')
        label_error.place(relx=0.5, rely=0.75, anchor='center')

        password_key_button = customtkinter.CTkButton(check_win, text="Enter",
                                                      command=check_password)
        password_key_button.place(relx=0.5, rely=0.85, anchor='center')

        check_win.attributes("-topmost", True)
        check_win.wait_window()
        app.focus_set()

    def user_policy():
        policy_win = customtkinter.CTkToplevel(app)
        screen_width = app.winfo_screenwidth()
        screen_height = app.winfo_screenheight()
        window_width = 600
        window_height = 400

        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        policy_win.geometry(f"{window_width}x{window_height}+{x}+{y}")
        policy_win.minsize(600, 400)
        policy_win.maxsize(600, 400)

        def on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        user_policy = """
             Welcome to VaultBuddy - Your Secure Password Manager

             **1. Introduction**

             Thank you for choosing VaultBuddy to keep your passwords secure. This User Policy outlines the terms and conditions governing your use of our app. By accessing or using VaultBuddy, you agree to comply with this User Policy and our Privacy Policy.

             **2. Account Creation and Security**

             2.1 Account Creation: To use VaultBuddy, you must create an account by providing accurate and up-to-date information. You are solely responsible for maintaining the confidentiality of your account credentials (username and password) and for all activities that occur under your account.

             2.2 Security: Please take necessary precautions to keep your account secure. Do not share your login information with anyone else, and ensure that you log out of your account after each session. In the event of any unauthorized access or suspicion of a security breach, immediately notify us at [contact email/phone number].

             **3. Data Privacy and Security**

             3.1 Data Collection and Storage: VaultBuddy takes data privacy seriously. We collect and store your passwords and associated data only for the purpose of providing our services to you. We do not sell, rent, or share your personal information with any third parties without your explicit consent, except as required by law.

             3.2 Encryption: All passwords and sensitive data are encrypted using industry-standard encryption protocols to ensure maximum security.

             3.3 Data Access: Our team strictly adheres to data access controls, and only authorized personnel with a legitimate need can access your data for support or technical reasons.

             **4. User Responsibilities**

             4.1 Data Accuracy: You are responsible for maintaining accurate and up-to-date information within your account.

             4.2 Usage Guidelines: You agree to use VaultBuddy only for lawful purposes and in compliance with all applicable laws and regulations.

             4.3 Prohibited Activities: You must not engage in any activities that could harm the app, its users, or violate any laws. Prohibited activities include but are not limited to hacking, phishing, spamming, and distributing malicious software.

             **5. App Updates and Maintenance**

             5.1 Updates: We may release app updates from time to time to improve functionality and security. You are encouraged to keep your app version up to date.

             5.2 Maintenance: While we strive to provide a smooth and uninterrupted experience, we may need to perform periodic maintenance. We will try to schedule these maintenance windows during low-traffic periods.

             **6. Termination**

             6.1 Account Termination: You may terminate your account at any time by following the app's instructions. All data associated with your account will be deleted upon termination.

             6.2 Termination by VaultBuddy: We reserve the right to terminate or suspend your account if we suspect any violation of this User Policy or if it is required by law.

             **7. Changes to User Policy**

             7.1 Updates: We may update this User Policy from time to time. Any changes will be posted on the app or communicated via email.

             7.2 Acceptance: By continuing to use VaultBuddy after changes to the User Policy, you are deemed to have accepted the revised terms.

             If you have any questions or concerns regarding this User Policy, please contact our support team at [support email/phone number].

             Last updated: [Date of last update]
             """

        canvas = customtkinter.CTkCanvas(policy_win, bg="white")
        canvas.pack(side=customtkinter.LEFT, fill=customtkinter.BOTH, expand=True)

        scrollbar = customtkinter.CTkScrollbar(policy_win, command=canvas.yview)
        scrollbar.pack(side=customtkinter.RIGHT, fill=customtkinter.Y)

        canvas.config(yscrollcommand=scrollbar.set)
        canvas.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind_all("<MouseWheel>", on_mousewheel)  # Bind mouse wheel event to canvas

        frame = customtkinter.CTkFrame(canvas, bg_color="white")
        canvas.create_window((0, 0), window=frame, anchor=customtkinter.NW)

        # Create a CTkLabel with improved styling
        policy_label = customtkinter.CTkLabel(frame, text=user_policy, bg_color="white", fg_color="black",
                                              justify=customtkinter.LEFT, wraplength=550,
                                              font=customtkinter.CTkFont(size=12))
        policy_label.pack(padx=20, pady=10, anchor=customtkinter.NW)

        policy_win.attributes("-topmost", True)
        policy_win.wait_window()
        app.focus_set()

    # wait window?
    def show_wait_message_box_and_set_file():
        app = tk.Tk()  # Create the main application window
        app.withdraw()  # Hide the main application window
        message = messagebox.askyesno("Loading", "Proceed to enter the app? (may take 10 seconds for load data)", icon='warning')

        if not message:
            # User clicked "No"
            app.destroy()
        else:
            # User clicked "Yes," continue with the rest of the code
            app.destroy()


    show_wait_message_box_and_set_file()

    # file_names = ("asdffdas.db","zxcvvczx.db", "huh.db")
    #
    # def set_permissions(file_name):
    #     file_path = get_file_path(file_name)
    #     set_file_permissions(file_path)
    #
    # for file_name in file_names:
    #     set_permissions(file_name)

    # canvas frame configure

    def choosing_frame_follow_name(name):
        home_button.configure(fg_color=("gray75", "gray25") if name == "Home" else "transparent")
        password_generator_button.configure(fg_color=("gray75", "gray25") if name == "Password Generator" else "transparent")
        password_checking_button.configure(fg_color=("gray75", "gray25") if name == "Password Checker" else "transparent")
        password_hashing_button.configure(fg_color=("gray75", "gray25") if name == "Password Hasher" else "transparent")
        password_manager_button.configure(fg_color=("gray75", "gray25") if name == "Password Manager" else "transparent")
        password_setting_button.configure(fg_color=("gray75", "gray25") if name == "Setting" else "transparent")

        if name == "Home":
            home_frame.grid(row=0, column=1, sticky='nsew')
        else:
            home_frame.grid_forget()
        if name == "Password Generator":
            password_generator_frame.grid(row=0, column=1, sticky="nsew")
        else:
            password_generator_frame.grid_forget()
        if name == "Password Checker":
            password_checking_frame.grid(row=0, column=1, sticky="nsew")
        else:
            password_checking_frame.grid_forget()
        if name == "Password Hasher":
            password_hashing_frame.grid(row=0, column=1, sticky='nsew')
        else:
            password_hashing_frame.grid_forget()
        if name == "Password Manager":
            data = load_data()
            show_encryption_key()
        else:
            password_manager_frame.grid_forget()
            password_manager_find_entry.delete(0, "end")
        if name == "Setting":
            password_setting_frame.grid(row=0, column=1, sticky='nsew')
        else:
            password_setting_frame.grid_forget()

    def home_event():
        choosing_frame_follow_name("Home")

    def password_generator_event():
        choosing_frame_follow_name("Password Generator")

    def password_checking_event():
        choosing_frame_follow_name("Password Checker")

    def password_hashing_event():
        choosing_frame_follow_name("Password Hasher")

    def password_manager_event():
        choosing_frame_follow_name("Password Manager")

    def setting_event():
        choosing_frame_follow_name("Setting")

    def changing_appearance(new_appearance_mode):
        customtkinter.set_appearance_mode(new_appearance_mode)

    # grid layout things (v0.2)
    app.grid_rowconfigure(0, weight=1)
    app.grid_columnconfigure(1, weight=1)

    # navigation frame (v0.2)
    navigation_frame_main = customtkinter.CTkFrame(app, corner_radius=0)
    navigation_frame_main.grid(row=0, column=0, sticky="nsew")
    navigation_frame_main.grid_rowconfigure(7, weight=1)
    logo_label = customtkinter.CTkLabel(navigation_frame_main, text='VaultBuddy',
                                        font=customtkinter.CTkFont(size=18, weight="bold"))
    logo_label.grid(row=0, column=0, padx=20, pady=20)
    home_button = customtkinter.CTkButton(navigation_frame_main, corner_radius=10, height=50,
                                          border_spacing=10, text='Home',
                                          fg_color="transparent", text_color=("gray10", "gray90"),
                                          hover_color=("gray70", "gray30"), anchor='',
                                          command=home_event)
    home_button.grid(row=1, column=0, sticky='ew')
    password_generator_button = customtkinter.CTkButton(navigation_frame_main, corner_radius=10, height=50,
                                                        border_spacing=10, text='Password Generator',
                                                        fg_color="transparent", text_color=("gray10", "gray90"),
                                                        hover_color=("gray70", "gray30"), anchor='',
                                                        command=password_generator_event)
    password_generator_button.grid(row=2, column=0, sticky='ew')
    password_checking_button = customtkinter.CTkButton(navigation_frame_main, corner_radius=10, height=50,
                                                       border_spacing=10, text='Password Checker',
                                                       fg_color="transparent", text_color=("gray10", "gray90"),
                                                       hover_color=("gray70", "gray30"), anchor='',
                                                       command=password_checking_event)
    password_checking_button.grid(row=3, column=0, sticky='ew')
    password_hashing_button = customtkinter.CTkButton(navigation_frame_main, corner_radius=10, height=50,
                                                      border_spacing=10, text='Password Hasher',
                                                      fg_color="transparent", text_color=("gray10", "gray90"),
                                                      hover_color=("gray70", "gray30"), anchor='',
                                                      command=password_hashing_event)
    password_hashing_button.grid(row=4, column=0, sticky='ew')
    password_manager_button = customtkinter.CTkButton(navigation_frame_main, corner_radius=10, height=50,
                                                      border_spacing=10, text='Password Manager',
                                                      fg_color="transparent", text_color=("gray10", "gray90"),
                                                      hover_color=("gray70", "gray30"), anchor='',
                                                      command=password_manager_event)
    password_manager_button.grid(row=5, column=0, sticky='ew')
    password_setting_button = customtkinter.CTkButton(navigation_frame_main, corner_radius=10, height=50,
                                                      border_spacing=10, text='Setting',
                                                      fg_color="transparent", text_color=("gray10", "gray90"),
                                                      hover_color=("gray70", "gray30"), anchor='',
                                                      command=setting_event)
    password_setting_button.grid(row=6, column=0, sticky='ew')

    change_appearance_menu = customtkinter.CTkOptionMenu(navigation_frame_main, values=["Dark", "Light", "System"],
                                                         command=changing_appearance, corner_radius=5)
    change_appearance_menu.grid(row=8, column=0, padx=20, pady=20, sticky='')

    # Home Frame
    home_frame = customtkinter.CTkFrame(app, corner_radius=5, fg_color="transparent")
    home_frame.grid_columnconfigure(0, weight=1)
    home_frame.grid_rowconfigure((0,1,2,3,4), weight=1, uniform='a')
    home_label = customtkinter.CTkLabel(home_frame, text="Welcome to VaultBuddy \nYour Secure Password Manager ",
                                        font=customtkinter.CTkFont(size=25, weight="bold"))
    home_label.grid(row=0, column=0, columnspan=3,padx=10, pady=10)
    home_label1 = customtkinter.CTkLabel(home_frame, text="This is the Demo of the app, there will be some bugs or some error while running.",
                                        font=customtkinter.CTkFont(size=15, weight="normal"))
    home_label1.place(relx=0.5, rely=0.2, anchor="center")
    home_label2 = customtkinter.CTkLabel(home_frame,text="Our Facebook:",
                                         font=customtkinter.CTkFont(size=15, weight="normal"))
    home_label2.place(relx=0.02, rely=0.8)
    home_label_button2 = customtkinter.CTkButton(home_frame, text="Hyperlink Button",font=customtkinter.CTkFont(size=13, weight="normal") )
    home_label_button2.place(relx=0.2, rely=0.8)
    home_label3 = customtkinter.CTkLabel(home_frame, text="Our Website:",
                                         font=customtkinter.CTkFont(size=15, weight="normal"))
    home_label3.place(relx=0.02, rely=0.85)
    home_label_button3 = customtkinter.CTkButton(home_frame, text="Hyperlink Button",
                                                 font=customtkinter.CTkFont(size=13, weight="normal"))
    home_label_button3.place(relx=0.2, rely=0.85)
    home_label4 = customtkinter.CTkLabel(home_frame, text="Our Contact:",
                                         font=customtkinter.CTkFont(size=15, weight="normal"))
    home_label4.place(relx=0.02, rely=0.9)
    home_label5 = customtkinter.CTkLabel(home_frame, text="0933432121",
                                         font=customtkinter.CTkFont(size=15, weight="normal"))
    home_label5.place(relx=0.25, rely=0.9)


    # Password Generator Frame
    password_generator_frame = customtkinter.CTkFrame(app, corner_radius=5, fg_color="transparent")
    password_generator_frame.grid_columnconfigure(0, weight=1)
    password_generator_frame.grid_rowconfigure(10, weight=1, uniform='a')

    password_generator_label1 = customtkinter.CTkLabel(password_generator_frame, text='Password Generator',
                                                       font=customtkinter.CTkFont(size=25, weight="bold"))
    password_generator_label1.grid(row=0, column=0, pady=20)
    password_generator_label2 = customtkinter.CTkLabel(password_generator_frame,
                                                       text="Generator to generate a random password",
                                                       font=customtkinter.CTkFont(size=16, weight="bold"))
    password_generator_label2.place(relx=0.5, rely=0.13, anchor='center')
    password_generator_label3 = customtkinter.CTkLabel(password_generator_frame, text="Generator Output:",
                                                       font=customtkinter.CTkFont(size=15, weight="bold"))
    password_generator_label3.place(relx=0.02, rely=0.2, anchor='w')
    password_generator_entry = customtkinter.CTkEntry(password_generator_frame, state='readonly',
                                                      font=customtkinter.CTkFont(size=16, weight="bold"),
                                                      justify='center', height=110, corner_radius=5)
    password_generator_entry.place(relx=0.5, rely=0.33, relwidth=0.95, anchor='center')
    password_generator_line = customtkinter.CTkFrame(password_generator_frame, height=1.7,
                                                     fg_color=("black", "light grey"))
    password_generator_line.place(relx=0.5, rely=0.54, anchor="center", relwidth=0.98)
    password_generator_label3 = customtkinter.CTkLabel(password_generator_frame, text="Password options:",
                                                       font=customtkinter.CTkFont(size=16, weight="bold"))
    password_generator_label3.place(relx=0.16, rely=0.6, anchor='center')
    password_generator_labelrecommend = customtkinter.CTkLabel(password_generator_frame,
                                                               text="It is recommend to tick all the boxes to create strong password.",
                                                               font=customtkinter.CTkFont(size=15, weight="normal"))
    password_generator_labelrecommend.place(relx=0.035, rely=0.65, anchor='w')
    password_generator_label4 = customtkinter.CTkLabel(password_generator_frame, text="Password Length",
                                                       font=customtkinter.CTkFont(size=14, weight="normal"))
    password_generator_label4.place(relx=0.251, rely=0.72, anchor='center')
    length_entry = customtkinter.CTkEntry(password_generator_frame,
                                          font=customtkinter.CTkFont(size=13, weight="normal"), width=50)
    length_entry.place(relx=0.087, rely=0.72, anchor='center')
    lowercase_var = tk.BooleanVar()
    lowercase_check_button = customtkinter.CTkCheckBox(password_generator_frame,
                                                       text="        Include lowercase character",
                                                       variable=lowercase_var,
                                                       font=customtkinter.CTkFont(size=14, weight="normal")
                                                       )
    lowercase_check_button.place(relx=0.26, rely=0.79, anchor='center')
    uppercase_var = tk.BooleanVar()
    uppercase_check_button = customtkinter.CTkCheckBox(password_generator_frame,
                                                       text="        Include uppercase character",
                                                       variable=uppercase_var,
                                                       font=customtkinter.CTkFont(size=14, weight="normal"))
    uppercase_check_button.place(relx=0.26, rely=0.86, anchor='center')
    specialchar_var = tk.BooleanVar()
    specialchar_check_button = customtkinter.CTkCheckBox(password_generator_frame,
                                                         text="        Include special character",
                                                         variable=specialchar_var)
    specialchar_check_button.place(relx=0.75, rely=0.72, anchor='center')
    digit_var = tk.BooleanVar()
    digit_check_button = customtkinter.CTkCheckBox(password_generator_frame, text="        Include digit",
                                                   variable=digit_var)
    digit_check_button.place(relx=0.6884, rely=0.79, anchor='center')
    generate_button = customtkinter.CTkButton(password_generator_frame, text="Generate Password", width=70,
                                              command=check_users_check_box,
                                              font=customtkinter.CTkFont(size=14, weight="normal"))
    generate_button.place(relx=0.5, rely=0.92, anchor='center')
    password_generator_label5 = customtkinter.CTkLabel(password_generator_frame, text="",
                                                       font=customtkinter.CTkFont(size=13, weight="normal"),
                                                       text_color='red')
    password_generator_label5.place(relx=0.5, rely=0.97, anchor='center')
    copy_button = customtkinter.CTkButton(password_generator_frame, text="Copy Password", width=70, state='disabled',
                                          command=copy_password_and_save_password,
                                          font=customtkinter.CTkFont(size=14, weight="normal"))
    copy_button.place(relx=0.5, rely=0.485, anchor='center')

    # Password Checker Frame
    password_checking_frame = customtkinter.CTkFrame(app, corner_radius=5, fg_color="transparent")
    password_checking_frame.grid_columnconfigure(0, weight=1)
    password_checking_frame.grid_rowconfigure(6, weight=1)
    password_checking_label1 = customtkinter.CTkLabel(password_checking_frame, text="Password Checker",
                                                      font=customtkinter.CTkFont(size=25, weight="bold"))
    password_checking_label1.grid(row=0, column=0, padx=20, pady=20)
    password_checking_label2 = customtkinter.CTkLabel(password_checking_frame,
                                                      text='Checker for the password to see if they met strong password policy',
                                                      font=customtkinter.CTkFont(size=16, weight="bold"))
    password_checking_label2.place(relx=0.5, rely=0.13, anchor='center')
    password_checking_label3 = customtkinter.CTkLabel(password_checking_frame, text='Enter your password here:',
                                                      font=customtkinter.CTkFont(size=15, weight="bold"))
    password_checking_label3.place(relx=0.02, rely=0.23, anchor='w')
    password_checking_entry = customtkinter.CTkEntry(password_checking_frame,
                                                     font=customtkinter.CTkFont(size=18, weight="normal"), height=110,
                                                     justify='center', corner_radius=5)
    password_checking_entry.place(relx=0.5, rely=0.36, anchor='center', relwidth=0.95)
    testpassword_line_frame = customtkinter.CTkFrame(password_checking_frame, height=1.7,
                                                     fg_color=("black", "light grey"))
    testpassword_line_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.98)

    password_checking_strength = customtkinter.CTkLabel(password_checking_frame,
                                                        text="Password strength",
                                                        font=customtkinter.CTkFont(size=16, weight="bold"))
    password_checking_strength.place(relx=0.5, rely=0.56, anchor='center')

    # For create strength parameter

    password_checking_progressbar = customtkinter.CTkProgressBar(password_checking_frame, mode='determinate',
                                                                 width=500, progress_color='black', height=20)
    password_checking_progressbar.place(relx=0.5, rely=0.64, anchor='center')
    password_checking_progressbar.set(value=-1)

    # Create a comment for the password strength
    password_checking_strength_comment = customtkinter.CTkLabel(password_checking_frame,
                                                                text='Please Enter Password',
                                                                font=customtkinter.CTkFont(size=14, weight='normal'))
    password_checking_strength_comment.place(relx=0.5, rely=0.72, anchor='center')

    # For create checkbox
    password_checking_checkbox_frame = customtkinter.CTkFrame(password_checking_frame)
    password_checking_checkbox_frame.place(relx=0.5, rely=0.865, anchor='center', relwidth=0.96, relheight=0.18)
    password_checking_length_checkbutton_var = tk.BooleanVar()
    password_checking_uppercase_checkbutton_var = tk.BooleanVar()
    password_checking_lowercase_checkbutton_var = tk.BooleanVar()
    password_checking_digit_checkbutton_var = tk.BooleanVar()
    password_checking_special_checkbutton_var = tk.BooleanVar()
    password_checking_length_checkbutton = customtkinter.CTkCheckBox(password_checking_checkbox_frame,
                                                                     text='Length (above 8 characters)',
                                                                     variable=password_checking_length_checkbutton_var,
                                                                     state='view-only',
                                                                     font=customtkinter.CTkFont(size=14,
                                                                                                weight="normal"))
    password_checking_length_checkbutton.place(rely=0.3, relx=0.21, anchor='center')
    password_checking_uppercase_checkbutton = customtkinter.CTkCheckBox(password_checking_checkbox_frame,
                                                                        text='Uppercase letter',
                                                                        variable=password_checking_uppercase_checkbutton_var,
                                                                        state='view-only',
                                                                        font=customtkinter.CTkFont(size=14,
                                                                                                   weight="normal"))
    password_checking_uppercase_checkbutton.place(rely=0.3, relx=0.515, anchor='center')
    password_checking_lowercase_checkbutton = customtkinter.CTkCheckBox(password_checking_checkbox_frame,
                                                                        text='Lowercase letter',
                                                                        variable=password_checking_lowercase_checkbutton_var,
                                                                        state='view-only',
                                                                        font=customtkinter.CTkFont(size=14,
                                                                                                   weight="normal"))
    password_checking_lowercase_checkbutton.place(rely=0.3, relx=0.84, anchor='center')
    password_checking_digit_checkbutton = customtkinter.CTkCheckBox(password_checking_checkbox_frame,
                                                                    text='Digits                     ',
                                                                    variable=password_checking_digit_checkbutton_var,
                                                                    state='view-only',
                                                                    font=customtkinter.CTkFont(size=14,
                                                                                               weight="normal"))
    password_checking_digit_checkbutton.place(rely=0.7, relx=0.14, anchor='center')
    password_checking_special_checkbutton = customtkinter.CTkCheckBox(password_checking_checkbox_frame,
                                                                      text='Special Character',
                                                                      variable=password_checking_special_checkbutton_var,
                                                                      state='view-only',
                                                                      font=customtkinter.CTkFont(size=14,
                                                                                                 weight="normal"))
    password_checking_special_checkbutton.place(rely=0.7, relx=0.523, anchor='center')

    password_checking_entry.bind('<Key>', update_password_progressbar)
    password_checking_entry.bind('<KeyRelease>', update_password_progressbar)
    password_checking_entry.bind('<Key>', changing_follow_entry)
    password_checking_entry.bind('<KeyRelease>', changing_follow_entry)
    password_checking_entry.bind('<Key>', password_strength_comment)
    password_checking_entry.bind('<KeyRelease>', password_strength_comment)

    # Password Hasher Frame
    password_hashing_frame = customtkinter.CTkFrame(app, corner_radius=5, fg_color="transparent")
    password_hashing_frame.grid_columnconfigure(0, weight=1)
    password_hashing_frame.grid_rowconfigure(6, weight=1)
    password_hashing_label1 = customtkinter.CTkLabel(password_hashing_frame, text="Password Hasher",
                                                     font=customtkinter.CTkFont(size=25, weight="bold"))
    password_hashing_label1.grid(row=0, column=0, padx=20, pady=20)
    password_hashing_label2 = customtkinter.CTkLabel(password_hashing_frame, text="See how Argon2 hash the password",
                                                     font=customtkinter.CTkFont(size=16, weight="bold"))
    password_hashing_label2.place(relx=0.5, rely=0.13, anchor='center')
    password_hashing_label3 = customtkinter.CTkLabel(password_hashing_frame, text="Input your password:",
                                                     font=customtkinter.CTkFont(size=15, weight="bold"))
    password_hashing_label3.place(relx=0.02, rely=0.2, anchor='w')
    password_hashing_entry = customtkinter.CTkEntry(password_hashing_frame,
                                                    font=customtkinter.CTkFont(size=15, weight="bold"),
                                                    justify='center', height=70, corner_radius=5)
    password_hashing_entry.place(relx=0.5, rely=0.295, relwidth=0.95, anchor='center')
    password_hashing_salt_label = customtkinter.CTkLabel(password_hashing_frame, text="Salt for the password:",
                                                         font=customtkinter.CTkFont(size=15, weight="bold"))
    password_hashing_salt_label.place(relx=0.02, rely=0.4, anchor='w')
    password_hashing_salt_entry = customtkinter.CTkEntry(password_hashing_frame,
                                                         font=customtkinter.CTkFont(size=15, weight="bold"),
                                                         justify='center', corner_radius=5)
    password_hashing_salt_entry.place(relx=0.65, rely=0.4, relwidth=0.63, anchor='center')
    password_hashing_arrow = customtkinter.CTkLabel(password_hashing_frame, text="\u2193",
                                                    font=customtkinter.CTkFont(size=20), text_color='#1F6AA5')
    password_hashing_arrow.place(relx=0.5, rely=0.46, anchor='center')
    password_hashing_label4 = customtkinter.CTkLabel(password_hashing_frame, text="Output in HEX form:",
                                                     font=customtkinter.CTkFont(size=15, weight="bold"))
    password_hashing_label4.place(relx=0.02, rely=0.50, anchor='w')
    password_hashing_result_entry = customtkinter.CTkEntry(password_hashing_frame,
                                                           font=customtkinter.CTkFont(size=15, weight="bold"),
                                                           justify='center', height=55, corner_radius=5,
                                                           state='disable')
    password_hashing_result_entry.place(relx=0.5, rely=0.585, anchor='center', relwidth=0.95)
    password_hashing_label5 = customtkinter.CTkLabel(password_hashing_frame, text="Output in Encoded form:",
                                                     font=customtkinter.CTkFont(size=15, weight="bold"))
    password_hashing_label5.place(relx=0.02, rely=0.67, anchor='w')
    password_hashing_result2_entry = customtkinter.CTkEntry(password_hashing_frame,
                                                            font=customtkinter.CTkFont(size=15, weight="bold"),
                                                            justify='center', height=55, corner_radius=5,
                                                            state='disable')
    password_hashing_result2_entry.place(relx=0.5, rely=0.755, anchor='center', relwidth=0.95)
    password_hashing_button = customtkinter.CTkButton(password_hashing_frame, text="Generate hash",
                                                      font=customtkinter.CTkFont(size=14, weight="normal"),
                                                      command=password_hashing, state='normal')
    password_hashing_button.place(relx=0.5, rely=0.86, anchor='center')
    password_hashing_error_label = customtkinter.CTkLabel(password_hashing_frame, text="",
                                                          font=customtkinter.CTkFont(size=14, weight="bold"),
                                                          text_color='red')
    password_hashing_error_label.place(relx=0.5, rely=0.94, anchor='center')
    password_hashing_fullview_button = customtkinter.CTkButton(password_hashing_frame, text="View full",
                                                               font=customtkinter.CTkFont(size=14, weight="normal"),
                                                               state='disabled', command=fullview1)
    password_hashing_fullview_button.place(relx=0.85, rely=0.5, anchor='center')
    password_hashing_fullview_button2 = customtkinter.CTkButton(password_hashing_frame, text="View full",
                                                                font=customtkinter.CTkFont(size=14, weight="normal"),
                                                                state='disabled', command=fullview2)
    password_hashing_fullview_button2.place(relx=0.85, rely=0.67, anchor='center')

    # making the mosuse

    def configure_canvas(event):
        canvas.itemconfigure(scroll_frame_window, width=event.width)

    def update_scroll_region(event):
        canvas.configure(scrollregion=canvas.bbox("all"))

    def on_mousewheel(event):
        canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")


    # Password Manager Frame
    password_manager_frame = customtkinter.CTkFrame(app, corner_radius=5, fg_color="transparent")
    password_manager_frame.grid_columnconfigure(0, weight=1)
    password_manager_frame.grid_rowconfigure(6, weight=1)
    password_manager_label1 = customtkinter.CTkLabel(
        password_manager_frame, text="Password Manager", font=customtkinter.CTkFont(size=25, weight="bold")
    )
    password_manager_label1.grid(row=0, column=0, padx=20, pady=20)
    password_manager_label2 = customtkinter.CTkLabel(password_manager_frame,
                                                     text="This windows can store your password securely",
                                                     font=customtkinter.CTkFont(size=16, weight="bold"),
                                                     )
    password_manager_label2.place(relx=0.5, rely=0.13, anchor="center")
    password_manager_find_entry = customtkinter.CTkEntry(password_manager_frame,
                                                         font=customtkinter.CTkFont(size=15, weight="bold"),
                                                         justify="left", corner_radius=20, height=40, width=550)
    password_manager_find_entry.place(relx=0.5, rely=0.21, anchor="center")
    password_manager_find_entry.insert(0, "Enter keyword to search...")
    password_manager_find_entry.bind("<FocusIn>", lambda event: password_manager_find_entry.delete(0, "end"))
    password_manager_find_entry.bind("<FocusOut>", lambda event: password_manager_find_entry.insert(0, "Enter keyword to search..."))
    password_manager_find_entry.bind("<Return>", lambda event: search_key(password_manager_find_entry.get()))
    password_manager_find_entry.bind("<Key>", lambda event: search_key(password_manager_find_entry.get()))
    password_manager_find_entry.bind("<KeyRelease>", lambda event: search_key(password_manager_find_entry.get()))
    canvas = customtkinter.CTkCanvas(password_manager_frame, width=550, height=350, background="#242424", highlightthickness=0)
    websitemain_label = customtkinter.CTkLabel(password_manager_frame, text="Website", font=customtkinter.CTkFont(size=15, weight="bold"), padx=10)
    websitemain_label.place(relx=0.245, rely=0.285, anchor="center")
    usernamemain_label = customtkinter.CTkLabel(password_manager_frame, text="Username", font=customtkinter.CTkFont(size=15, weight="bold"), padx=10)
    usernamemain_label.place(relx=0.504, rely=0.285, anchor="center")
    passwordmain_label = customtkinter.CTkLabel(password_manager_frame, text="Password", font=customtkinter.CTkFont(size=15, weight="bold"), padx=10)
    passwordmain_label.place(relx=0.755, rely=0.285, anchor="center")
    canvas.place(relx=0.5, rely=0.61, anchor="center")
    scroll_frame = customtkinter.CTkFrame(canvas)
    scroll_frame.bind("<Configure>", configure_canvas)
    scrollbar = customtkinter.CTkScrollbar(scroll_frame, command=canvas.yview)
    scrollbar.pack(side=customtkinter.RIGHT, fill=customtkinter.Y)
    scroll_frame.columnconfigure((0, 1, 2), weight=1)
    canvas.configure(yscrollcommand=scrollbar.set)
    scroll_frame_window = canvas.create_window((0, 0), window=scroll_frame, anchor="center", width=600)
    # default space
    canvas.bind("<Configure>", configure_canvas)
    canvas.bind_all("<MouseWheel>", on_mousewheel)
    scroll_frame.bind("<Configure>", update_scroll_region)

    def update_canvas_frame_height():
        num_rows = len(data)
        if num_rows > 9:
            canvas.itemconfigure(scroll_frame_window, height=False)
        else:
            canvas.itemconfigure(scroll_frame_window, height=350)

    initialize_database()

    password_manager_add_button = customtkinter.CTkButton(password_manager_frame, text="Add More",
                                                          font=customtkinter.CTkFont(size=14, weight="normal"),
                                                          corner_radius=20, height=40, width=60, command=insert_data)
    password_manager_add_button.place(relx=0.4, rely=0.95, anchor="center")
    password_manager_delete_button = customtkinter.CTkButton(password_manager_frame, text="   Delete   ",
                                                             font=customtkinter.CTkFont(size=14, weight="normal"),
                                                             corner_radius=20, height=40, width=60, state="disabled",
                                                             command=delete_follow_the_check)
    password_manager_delete_button.place(relx=0.6, rely=0.95, anchor="center")


    #setting_frame
    password_setting_frame = customtkinter.CTkFrame(app, corner_radius=5, fg_color="transparent")
    password_setting_frame.grid_columnconfigure(0, weight=1)
    password_setting_frame.grid_rowconfigure(0, weight=1, uniform='b')
    password_setting_frame.grid_rowconfigure((1,2,3), weight=2, uniform='b')

    setting_label1 = customtkinter.CTkLabel(password_setting_frame, text="App Setting",
                                                     font=customtkinter.CTkFont(size=25, weight="bold"))
    setting_label1.grid(row=0, column=0, padx=20, pady=20, sticky='nsew')
    setting_button1 = customtkinter.CTkButton(password_setting_frame, text="Sign out", font=customtkinter.CTkFont(size=23, weight="normal"), command=sign_out)
    setting_button1.grid(row=1, column=0, padx=10, pady=10, sticky='nsew')
    setting_button1 = customtkinter.CTkButton(password_setting_frame, text="Reset Data",
                                              font=customtkinter.CTkFont(size=23, weight="normal"), command=reset)
    setting_button1.grid(row=2, column=0, padx=10, pady=10, sticky='nsew')
    setting_button1 = customtkinter.CTkButton(password_setting_frame, text="User Policy",
                                              font=customtkinter.CTkFont(size=23, weight="normal"), command=user_policy)
    setting_button1.grid(row=3, column=0, padx=10, pady=10, sticky='nsew')
    # default frame
    choosing_frame_follow_name("Home")

cursor.execute("SELECT * FROM masterpassword")

if cursor.fetchall():
    real_login()
else:
    first_time_login()

app.mainloop()
