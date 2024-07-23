import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import json
import random
import string
import pyperclip
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from datetime import datetime
import csv
import webbrowser

class CPSecurePassPro:
    def __init__(self, master):
        self.master = master
        self.master.title("CP SecurePass Pro")
        self.master.geometry("900x600")
        self.master.resizable(True, True)

        self.style = ttk.Style()
        self.dark_mode = tk.BooleanVar(value=False)
        self.passwords = {}
        self.key = None
        self.load_key()
        self.create_widgets()
        self.load_passwords()
        self.dark_mode_switch.set(self.dark_mode.get())
        self.configure_styles()


    def configure_styles(self):
        print(f"Configuring styles. Dark mode: {self.dark_mode.get()}")  # Debug print
        if self.dark_mode.get():
            self.style.theme_use("clam")
            bg_color = "#2E2E2E"
            fg_color = "#FFFFFF"
            accent_color = "#4A90E2"
        else:
            self.style.theme_use("clam")
            bg_color = "#F0F0F0"
            fg_color = "#333333"
            accent_color = "#4A90E2"

        self.style.configure(".", background=bg_color, foreground=fg_color)
        self.style.configure("TFrame", background=bg_color)
        self.style.configure("TLabel", background=bg_color, foreground=fg_color)
        self.style.configure("TButton", background=accent_color, foreground="white")
        self.style.map("TButton", background=[('active', self.lighten_color(accent_color))])
        self.style.configure("TEntry", fieldbackground=bg_color, foreground=fg_color)
        self.style.configure("TCheckbutton", background=bg_color, foreground=fg_color)
        self.style.configure("Treeview", background=bg_color, fieldbackground=bg_color, foreground=fg_color)
        self.style.configure("Treeview.Heading", background=accent_color, foreground="white")
        self.style.configure("TNotebook", background=bg_color)
        self.style.configure("TNotebook.Tab", background=bg_color, foreground=fg_color)
        self.style.map("TNotebook.Tab", background=[("selected", accent_color)], foreground=[("selected", "white")])

        # Update the root window background
        self.master.configure(background=bg_color)

        # Force update of all widgets
        self.update_ui_colors()


    def lighten_color(self, color):
        r, g, b = [int(color[i:i+2], 16) for i in (1, 3, 5)]
        factor = 1.3
        r, g, b = [min(int(c * factor), 255) for c in (r, g, b)]
        return f"#{r:02x}{g:02x}{b:02x}"

    def create_widgets(self):
        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=10)

        self.create_passwords_tab()
        self.create_generator_tab()
        self.create_settings_tab()
        self.create_about_tab()

    def create_passwords_tab(self):
        passwords_frame = ttk.Frame(self.notebook)
        self.notebook.add(passwords_frame, text="Passwords")

        search_frame = ttk.Frame(passwords_frame)
        search_frame.pack(fill="x", padx=10, pady=10)
        ttk.Label(search_frame, text="Search:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.search_passwords)
        ttk.Entry(search_frame, textvariable=self.search_var, width=30).pack(side="left", padx=5)

        tree_frame = ttk.Frame(passwords_frame)
        tree_frame.pack(expand=True, fill="both", padx=10, pady=10)

        self.tree = ttk.Treeview(tree_frame, columns=("Website", "Username", "Last Modified"), show="headings")
        self.tree.heading("Website", text="Website")
        self.tree.heading("Username", text="Username")
        self.tree.heading("Last Modified", text="Last Modified")
        self.tree.column("Website", width=200)
        self.tree.column("Username", width=150)
        self.tree.column("Last Modified", width=150)
        self.tree.pack(side="left", expand=True, fill="both")

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)

        button_frame = ttk.Frame(passwords_frame)
        button_frame.pack(fill="x", padx=10, pady=10)

        ttk.Button(button_frame, text="Add Password", command=self.add_password).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Get Password", command=self.get_password).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Edit Password", command=self.edit_password).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Delete Password", command=self.delete_password).pack(side="left", padx=5)

    def create_generator_tab(self):
        generator_frame = ttk.Frame(self.notebook)
        self.notebook.add(generator_frame, text="Password Generator")

        ttk.Label(generator_frame, text="Password Length:").grid(row=0, column=0, padx=10, pady=10, sticky="e")
        self.length_var = tk.IntVar(value=16)
        ttk.Spinbox(generator_frame, from_=8, to=64, textvariable=self.length_var, width=5).grid(row=0, column=1, padx=10, pady=10, sticky="w")

        self.use_uppercase = tk.BooleanVar(value=True)
        ttk.Checkbutton(generator_frame, text="Uppercase", variable=self.use_uppercase).grid(row=1, column=0, padx=10, pady=5, sticky="w")

        self.use_lowercase = tk.BooleanVar(value=True)
        ttk.Checkbutton(generator_frame, text="Lowercase", variable=self.use_lowercase).grid(row=2, column=0, padx=10, pady=5, sticky="w")

        self.use_digits = tk.BooleanVar(value=True)
        ttk.Checkbutton(generator_frame, text="Digits", variable=self.use_digits).grid(row=3, column=0, padx=10, pady=5, sticky="w")

        self.use_symbols = tk.BooleanVar(value=True)
        ttk.Checkbutton(generator_frame, text="Symbols", variable=self.use_symbols).grid(row=4, column=0, padx=10, pady=5, sticky="w")

        ttk.Button(generator_frame, text="Generate Password", command=self.generate_password).grid(row=5, column=0, columnspan=2, padx=10, pady=10)

        self.generated_password = tk.StringVar()
        ttk.Entry(generator_frame, textvariable=self.generated_password, state="readonly", width=40).grid(row=6, column=0, columnspan=2, padx=10, pady=10)

        ttk.Button(generator_frame, text="Copy to Clipboard", command=self.copy_generated_password).grid(row=7, column=0, columnspan=2, padx=10, pady=10)

    def create_settings_tab(self):
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="Settings")

        dark_mode_frame = ttk.Frame(settings_frame)
        dark_mode_frame.pack(pady=10)
        ttk.Label(dark_mode_frame, text="Dark Mode:").pack(side="left", padx=(0, 10))
        self.dark_mode_switch = Switch(dark_mode_frame, command=self.toggle_dark_mode)
        self.dark_mode_switch.pack(side="left")

        ttk.Button(settings_frame, text="Change Master Password", command=self.change_master_password).pack(pady=10)
        ttk.Button(settings_frame, text="Export Passwords", command=self.export_passwords).pack(pady=10)
        ttk.Button(settings_frame, text="Import Passwords", command=self.import_passwords).pack(pady=10)
        ttk.Button(settings_frame, text="Backup Passwords", command=self.backup_passwords).pack(pady=10)
        ttk.Button(settings_frame, text="Restore Passwords", command=self.restore_passwords).pack(pady=10)

    def create_about_tab(self):
        about_frame = ttk.Frame(self.notebook)
        self.notebook.add(about_frame, text="About")

        ttk.Label(about_frame, text="CP SecurePass Pro", font=('Helvetica', 16, 'bold')).pack(pady=20)
        ttk.Label(about_frame, text="Version 1.0").pack()
        ttk.Label(about_frame, text="© 2024 CP SecurePass Pro Team").pack(pady=10)
        ttk.Label(about_frame, text="A secure and user-friendly password management solution.").pack(pady=10)
        ttk.Button(about_frame, text="Visit Website", command=self.open_website).pack(pady=10)

    def open_website(self):
        webbrowser.open("https://example.com/cpsecurepasspro")

    def force_ui_update(self):
        self.master.update_idletasks()
        self.master.update()
    
    def toggle_dark_mode(self):
        print("Toggle dark mode called")  # Debug print
        self.dark_mode.set(self.dark_mode_switch.get())
        print(f"Dark mode is now: {self.dark_mode.get()}")  # Debug print
        self.configure_styles()
        self.update_ui_colors()
        self.force_ui_update()
        print("Styles and UI updated")  # Debug print


    def update_ui_colors(self):
        self.master.update()
        self.master.update_idletasks()
        
        for widget in self.master.winfo_children():
            self.update_widget_colors(widget)

    def update_widget_colors(self, widget):
        widget_type = widget.winfo_class()
        if widget_type in ('TFrame', 'TLabel', 'TButton', 'TEntry', 'TCheckbutton'):
            widget.configure(style=widget_type)
        elif widget_type == 'TNotebook':
            widget.configure(style='TNotebook')
            for tab in widget.winfo_children():
                self.update_widget_colors(tab)
        elif widget_type == 'Treeview':
            widget.configure(style='Treeview')
            widget.tag_configure('evenrow', background=self.style.lookup('Treeview', 'background'))
            widget.tag_configure('oddrow', background=self.style.lookup('Treeview', 'background'))
        
        for child in widget.winfo_children():
            self.update_widget_colors(child)

    def set_master_password(self):
        master_password = simpledialog.askstring("Master Password", "Set your master password:", show='*')
        if master_password:
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
            with open("master.key", "wb") as key_file:
                key_file.write(salt + key)
            self.key = key
        else:
            messagebox.showerror("Error", "Master password is required!")
            self.master.quit()

    def load_key(self):
        try:
            with open("master.key", "rb") as key_file:
                file_content = key_file.read()
                salt = file_content[:16]
                self.key = file_content[16:]
        except FileNotFoundError:
            self.set_master_password()

    def encrypt_password(self, password):
        f = Fernet(self.key)
        return f.encrypt(password.encode()).decode()

    def decrypt_password(self, encrypted_password):
        f = Fernet(self.key)
        return f.decrypt(encrypted_password.encode()).decode()

    def add_password(self):
        website = simpledialog.askstring("Website", "Enter the website:")
        username = simpledialog.askstring("Username", "Enter the username:")
        password = simpledialog.askstring("Password", "Enter the password:", show='*')

        if website and username and password:
            encrypted_password = self.encrypt_password(password)
            self.passwords[website] = {
                "username": username,
                "password": encrypted_password,
                "last_modified": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            self.save_passwords()
            self.update_treeview()
            messagebox.showinfo("Success", "Password added successfully!")
        else:
            messagebox.showerror("Error", "All fields are required!")

    def get_password(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a password to retrieve.")
            return

        website = self.tree.item(selected[0])['values'][0]
        username = self.passwords[website]["username"]
        decrypted_password = self.decrypt_password(self.passwords[website]["password"])
        pyperclip.copy(decrypted_password)
        messagebox.showinfo("Password Retrieved", f"Website: {website}\nUsername: {username}\nPassword copied to clipboard!")

    def edit_password(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a password to edit.")
            return

        website = self.tree.item(selected[0])['values'][0]
        username = simpledialog.askstring("Username", "Enter the new username:", initialvalue=self.passwords[website]["username"])
        password = simpledialog.askstring("Password", "Enter the new password:", show='*')

        if username and password:
            encrypted_password = self.encrypt_password(password)
            self.passwords[website] = {
                "username": username,
                "password": encrypted_password,
                "last_modified": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            self.save_passwords()
            self.update_treeview()
            messagebox.showinfo("Success", "Password updated successfully!")
        else:
            messagebox.showerror("Error", "Both username and password are required!")

    def delete_password(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a password to delete.")
            return

        website = self.tree.item(selected[0])['values'][0]
        confirm = messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete the password for {website}?")
        if confirm:
            del self.passwords[website]
            self.save_passwords()
            self.update_treeview()
            messagebox.showinfo("Success", "Password deleted successfully!")

    def generate_password(self):
        length = self.length_var.get()
        characters = ""
        if self.use_uppercase.get():
            characters += string.ascii_uppercase
        if self.use_lowercase.get():
            characters += string.ascii_lowercase
        if self.use_digits.get():
            characters += string.digits
        if self.use_symbols.get():
            characters += string.punctuation

        if not characters:
            messagebox.showerror("Error", "Please select at least one character type.")
            return

        password = ''.join(random.choice(characters) for _ in range(length))
        self.generated_password.set(password)

    def copy_generated_password(self):
        password = self.generated_password.get()
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Password Copied", "Generated password copied to clipboard!")
        else:
            messagebox.showerror("Error", "No password generated yet.")

    def save_passwords(self):
        with open("passwords.json", "w") as f:
            json.dump(self.passwords, f)

    def load_passwords(self):
        try:
            with open("passwords.json", "r") as f:
                self.passwords = json.load(f)
            self.update_treeview()
        except FileNotFoundError:
            self.passwords = {}

    def update_treeview(self):
        self.tree.delete(*self.tree.get_children())
        for website, data in self.passwords.items():
            self.tree.insert("", "end", values=(website, data["username"], data["last_modified"]))

    def search_passwords(self, *args):
        search_term = self.search_var.get().lower()
        self.tree.delete(*self.tree.get_children())
        for website, data in self.passwords.items():
            if search_term in website.lower() or search_term in data["username"].lower():
                self.tree.insert("", "end", values=(website, data["username"], data["last_modified"]))

    def change_master_password(self):
        old_password = simpledialog.askstring("Old Password", "Enter your current master password:", show='*')
        if old_password:
            new_password = simpledialog.askstring("New Password", "Enter your new master password:", show='*')
            if new_password:
                confirm_password = simpledialog.askstring("Confirm Password", "Confirm your new master password:", show='*')
                if new_password == confirm_password:
                    salt = os.urandom(16)
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                    )
                    new_key = base64.urlsafe_b64encode(kdf.derive(new_password.encode()))
                    
                    # Re-encrypt all passwords with the new key
                    new_passwords = {}
                    for website, data in self.passwords.items():
                        old_fernet = Fernet(self.key)
                        new_fernet = Fernet(new_key)
                        decrypted_password = old_fernet.decrypt(data["password"].encode()).decode()
                        new_encrypted_password = new_fernet.encrypt(decrypted_password.encode()).decode()
                        new_passwords[website] = {
                            "username": data["username"],
                            "password": new_encrypted_password,
                            "last_modified": data["last_modified"]
                        }
                    
                    self.passwords = new_passwords
                    self.key = new_key
                    
                    with open("master.key", "wb") as key_file:
                        key_file.write(salt + new_key)
                    
                    self.save_passwords()
                    messagebox.showinfo("Success", "Master password changed successfully!")
                else:
                    messagebox.showerror("Error", "New passwords do not match!")
            else:
                messagebox.showerror("Error", "New master password is required!")
        else:
            messagebox.showerror("Error", "Current master password is required!")

    def export_passwords(self):
        filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if filename:
            with open(filename, "w", newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Website", "Username", "Password", "Last Modified"])
                for website, data in self.passwords.items():
                    decrypted_password = self.decrypt_password(data["password"])
                    writer.writerow([website, data["username"], decrypted_password, data["last_modified"]])
            messagebox.showinfo("Success", f"Passwords exported to {filename}")

    def import_passwords(self):
        filename = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if filename:
            try:
                with open(filename, "r") as csvfile:
                    reader = csv.reader(csvfile)
                    next(reader)  # Skip header row
                    for row in reader:
                        website, username, password, last_modified = row
                        encrypted_password = self.encrypt_password(password)
                        self.passwords[website] = {
                            "username": username,
                            "password": encrypted_password,
                            "last_modified": last_modified
                        }
                self.save_passwords()
                self.update_treeview()
                messagebox.showinfo("Success", f"Passwords imported from {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import passwords: {str(e)}")

    def backup_passwords(self):
        backup_dir = filedialog.askdirectory(title="Select Backup Directory")
        if backup_dir:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = os.path.join(backup_dir, f"password_backup_{timestamp}.json")
            with open(backup_file, "w") as f:
                json.dump(self.passwords, f)
            messagebox.showinfo("Success", f"Passwords backed up to {backup_file}")

    def restore_passwords(self):
        backup_file = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if backup_file:
            try:
                with open(backup_file, "r") as f:
                    restored_passwords = json.load(f)
                self.passwords = restored_passwords
                self.save_passwords()
                self.update_treeview()
                messagebox.showinfo("Success", f"Passwords restored from {backup_file}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to restore passwords: {str(e)}")

class Switch(tk.Canvas):
    def __init__(self, master, command=None, **kwargs):
        super().__init__(master, width=60, height=30, **kwargs)
        self.command = command
        self.toggle_state = False
        self.bind("<Button-1>", self.toggle)
        self.draw()

    def draw(self):
        self.delete("all")
        bg_color = "#2E2E2E" if self.toggle_state else "#CCCCCC"
        fg_color = "#FFFFFF" if self.toggle_state else "#888888"
        self.create_rectangle(0, 0, 60, 30, outline="", fill=bg_color, width=0)
        self.create_oval(5 if not self.toggle_state else 35, 5, 25 if not self.toggle_state else 55, 25, fill=fg_color)

    def toggle(self, event=None):
        self.toggle_state = not self.toggle_state
        self.draw()
        if self.command:
            self.command()

    def get(self):
        return self.toggle_state

    def set(self, state):
        self.toggle_state = state
        self.draw()


if __name__ == "__main__":
    root = tk.Tk()
    app = CPSecurePassPro(root)
    root.mainloop()
    

