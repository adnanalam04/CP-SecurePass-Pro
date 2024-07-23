import sys
import json
import random
import string
import pyperclip
import base64
import os
import csv
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QLineEdit, QLabel, QStackedWidget, QTreeWidget, 
                             QTreeWidgetItem, QFrame, QSizePolicy, QFileDialog, QMessageBox,
                             QSpinBox, QCheckBox, QInputDialog)
from PyQt6.QtGui import QIcon, QFont, QColor, QPainter
from PyQt6.QtCore import Qt, QPropertyAnimation, QEasingCurve, QTimer, QSize, pyqtSignal

class ModernSwitch(QWidget):
    toggled = pyqtSignal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(60, 30)
        self._is_on = False
        self._track_color = QColor("#CCCCCC")
        self._thumb_color = QColor("#FFFFFF")
        self._animation = QPropertyAnimation(self, b"pos")
        self._animation.setDuration(200)
        self._animation.setEasingCurve(QEasingCurve.Type.InOutCubic)

    def update_colors(self, is_dark):
        self._track_color = QColor("#455A64") if is_dark else QColor("#BDBDBD")
        self._thumb_color = QColor("#90A4AE") if is_dark else QColor("#FAFAFA")
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(self._track_color)
        painter.drawRoundedRect(0, 0, 60, 30, 15, 15)

        painter.setBrush(self._thumb_color)
        if self._is_on:
            painter.drawEllipse(35, 5, 20, 20)
        else:
            painter.drawEllipse(5, 5, 20, 20)

    def mousePressEvent(self, event):
        self.toggle()

    def toggle(self):
        self._is_on = not self._is_on
        self._animation.setStartValue(self._thumb_color.lighter(150) if self._is_on else self._thumb_color.darker(150))
        self._animation.setEndValue(self._thumb_color)
        self._animation.start()
        self.toggled.emit(self._is_on)
        self.update()

class CPSecurePassPro(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CP SecurePass Pro")
        self.setGeometry(100, 100, 1000, 600)

        self.passwords = {}
        self.key = None
        self.load_key()
        self.load_passwords()
        self.init_ui()
        self.update_password_tree()

    def init_ui(self):
        main_layout = QHBoxLayout()
        
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setMinimumWidth(200)
        sidebar_layout = QVBoxLayout(sidebar)
        
        logo = QLabel("CP SecurePass Pro")
        logo.setObjectName("logo")
        sidebar_layout.addWidget(logo)
        
        nav_buttons = [
            ("Passwords", self.show_passwords),
            ("Generator", self.show_generator),
            ("Settings", self.show_settings),
            ("About", self.show_about)
        ]
        
        for text, func in nav_buttons:
            btn = QPushButton(text)
            btn.setObjectName("nav-button")
            btn.clicked.connect(func)
            sidebar_layout.addWidget(btn)
        
        sidebar_layout.addStretch()
        
        content = QWidget()
        content.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        content_layout = QVBoxLayout(content)
        
        self.stacked_widget = QStackedWidget()
        content_layout.addWidget(self.stacked_widget)
        
        self.passwords_page = self.create_passwords_page()
        self.generator_page = self.create_generator_page()
        self.settings_page = self.create_settings_page()
        self.about_page = self.create_about_page()
        
        self.stacked_widget.addWidget(self.passwords_page)
        self.stacked_widget.addWidget(self.generator_page)
        self.stacked_widget.addWidget(self.settings_page)
        self.stacked_widget.addWidget(self.about_page)
        
        main_layout.addWidget(sidebar)
        main_layout.addWidget(content, 1)
        
        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)
        
        self.apply_styles()

    def load_key(self):
        try:
            with open("master.key", "rb") as key_file:
                file_content = key_file.read()
                salt = file_content[:16]
                stored_key = file_content[16:]

            password, ok = QInputDialog.getText(self, "Master Password", "Enter your master password:", QLineEdit.EchoMode.Password)
            if not ok:
                QMessageBox.critical(self, "Error", "Master password is required!")
                sys.exit()

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

            if key != stored_key:
                QMessageBox.critical(self, "Error", "Incorrect master password!")
                sys.exit()

            self.key = key
        except FileNotFoundError:
            self.set_master_password()


    def create_passwords_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search passwords...")
        self.search_bar.textChanged.connect(self.search_passwords)
        layout.addWidget(self.search_bar)
        
        self.password_tree = QTreeWidget()
        self.password_tree.setHeaderLabels(["Website", "Username", "Last Modified"])
        layout.addWidget(self.password_tree)
        
        button_layout = QHBoxLayout()
        buttons = [
            ("Add", self.add_password),
            ("Edit", self.edit_password),
            ("Delete", self.delete_password),
            ("Copy Password", self.copy_password)
        ]
        for text, func in buttons:
            btn = QPushButton(text)
            btn.setObjectName("action-button")
            btn.clicked.connect(func)
            button_layout.addWidget(btn)
        
        layout.addLayout(button_layout)
        return page

    def create_generator_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        
        options_layout = QVBoxLayout()
        self.use_uppercase = QCheckBox("Uppercase")
        self.use_lowercase = QCheckBox("Lowercase")
        self.use_numbers = QCheckBox("Numbers")
        self.use_symbols = QCheckBox("Symbols")
        
        options = [self.use_uppercase, self.use_lowercase, self.use_numbers, self.use_symbols]
        for option in options:
            options_layout.addWidget(option)
        
        layout.addLayout(options_layout)
        
        length_layout = QHBoxLayout()
        length_layout.addWidget(QLabel("Password Length:"))
        self.length_input = QSpinBox()
        self.length_input.setRange(8, 64)
        self.length_input.setValue(16)
        length_layout.addWidget(self.length_input)
        layout.addLayout(length_layout)
        
        generate_btn = QPushButton("Generate Password")
        generate_btn.setObjectName("generate-button")
        generate_btn.clicked.connect(self.generate_password)
        layout.addWidget(generate_btn)
        
        self.password_display = QLineEdit()
        self.password_display.setReadOnly(True)
        self.password_display.setPlaceholderText("Generated password will appear here")
        layout.addWidget(self.password_display)
        
        copy_btn = QPushButton("Copy to Clipboard")
        copy_btn.setObjectName("copy-button")
        copy_btn.clicked.connect(self.copy_generated_password)
        layout.addWidget(copy_btn)
        
        return page

    def create_settings_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        
        dark_mode_layout = QHBoxLayout()
        dark_mode_layout.addWidget(QLabel("Dark Mode:"))
        self.dark_mode_switch = ModernSwitch()
        self.dark_mode_switch.toggled.connect(self.toggle_dark_mode)
        dark_mode_layout.addWidget(self.dark_mode_switch)
        layout.addLayout(dark_mode_layout)
        
        buttons = [
            ("Change Master Password", self.change_master_password),
            ("Export Passwords", self.export_passwords),
            ("Import Passwords", self.import_passwords),
            ("Backup Passwords", self.backup_passwords),
            ("Restore Passwords", self.restore_passwords)
        ]
        for text, func in buttons:
            btn = QPushButton(text)
            btn.setObjectName("settings-button")
            btn.clicked.connect(func)
            layout.addWidget(btn)
        
        return page

    def create_about_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        
        title = QLabel("CP SecurePass Pro")
        title.setObjectName("about-title")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        version = QLabel("Version 1.0")
        version.setObjectName("about-version")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(version)
        
        description = QLabel("A state-of-the-art password management solution\ndesigned for ultimate security and ease of use.")
        description.setObjectName("about-description")
        description.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(description)
        
        founder_title = QLabel("About the Founder")
        founder_title.setObjectName("founder-title")
        founder_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(founder_title)
        
        founder_info = QLabel(
            "Adnan Alam\n"
            "Founder and CEO, CP Secure Pvt Ltd\n\n"
            "Adnan Alam is a distinguished Cyber Security Expert and Software Developer "
            "with over a decade of experience in the field. As the founder of CP Secure Pvt Ltd, "
            "he has been at the forefront of developing innovative security solutions for businesses "
            "and individuals alike.\n\n"
            "With a passion for digital security and a keen eye for emerging threats, Adnan has "
            "dedicated his career to creating robust, user-friendly tools that empower people to "
            "protect their digital lives. CP SecurePass Pro is a testament to his commitment to "
            "combining cutting-edge security measures with intuitive design.\n\n"
            "Adnan's expertise spans across various domains of cybersecurity, including:\n"
            "• Penetration Testing\n"
            "• Secure Software Development\n"
            "• Cryptography\n"
            "• Network Security\n"
            "• Threat Intelligence\n\n"
            "Through CP Secure Pvt Ltd, Adnan continues to push the boundaries of what's possible "
            "in cybersecurity, always staying one step ahead of potential threats."
        )
        founder_info.setObjectName("founder-info")
        founder_info.setWordWrap(True)
        founder_info.setAlignment(Qt.AlignmentFlag.AlignJustify)
        layout.addWidget(founder_info)
        
        visit_website_btn = QPushButton("Visit CP Secure Website")
        visit_website_btn.setObjectName("visit-website-button")
        visit_website_btn.clicked.connect(self.visit_website)
        layout.addWidget(visit_website_btn)
        
        contact_btn = QPushButton("Contact Us")
        contact_btn.setObjectName("contact-button")
        contact_btn.clicked.connect(self.show_contact_info)
        layout.addWidget(contact_btn)
        
        return page

    def visit_website(self):
        import webbrowser
        webbrowser.open("https://www.linkedin.com/in/adnanalam04/")  # Replace with your actual website

    def show_contact_info(self):
        QMessageBox.information(self, "Contact Information", 
                                "Email: adnanalam0004@gmail.com\n"
                                "Phone: +91 8178756228\n"
                                "Address: New Delhi")


    def show_passwords(self):
        self.stacked_widget.setCurrentIndex(0)

    def show_generator(self):
        self.stacked_widget.setCurrentIndex(1)

    def show_settings(self):
        self.stacked_widget.setCurrentIndex(2)

    def show_about(self):
        self.stacked_widget.setCurrentIndex(3)

    def apply_styles(self):
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #F5F5F5;
                color: #212121;
            }
            #sidebar {
                background-color: #1976D2;
                color: #FFFFFF;
                min-width: 200px;
                padding: 20px;
            }
            #logo {
                font-size: 24px;
                font-weight: bold;
                margin-bottom: 20px;
            }
            #nav-button {
                background-color: transparent;
                color: #FFFFFF;
                border: none;
                padding: 10px;
                text-align: left;
                font-size: 16px;
            }
            #nav-button:hover {
                background-color: #1E88E5;
            }
            QLineEdit, QTreeWidget, QSpinBox {
                background-color: #FFFFFF;
                color: #212121;
                border: 1px solid #BDBDBD;
                padding: 5px;
                border-radius: 3px;
            }
            QPushButton {
                background-color: #1976D2;
                color: #FFFFFF;
                border: none;
                padding: 8px 15px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #1E88E5;
            }
            QTreeWidget::item:selected {
                background-color: #BBDEFB;
                color: #212121;
            }
            #about-title {
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 10px;
        }
        #about-version {
            font-size: 16px;
            color: #666;
            margin-bottom: 20px;
        }
        #about-description {
            font-size: 14px;
            margin-bottom: 30px;
        }
        #founder-title {
            font-size: 20px;
            font-weight: bold;
            margin-top: 20px;
            margin-bottom: 10px;
        }
        #founder-info {
            font-size: 14px;
            line-height: 1.4;
            margin-bottom: 20px;
        }
        #visit-website-button, #contact-button {
            font-size: 14px;
            padding: 10px 20px;
            margin-top: 10px;
        """)

    def set_master_password(self):
        password, ok = QInputDialog.getText(self, "Master Password", "Set your master password:", QLineEdit.EchoMode.Password)
        if ok and password:
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            with open("master.key", "wb") as key_file:
                key_file.write(salt + key)
            self.key = key
        else:
            QMessageBox.critical(self, "Error", "Master password is required!")
            sys.exit()

    def encrypt_password(self, password):
        f = Fernet(self.key)
        return f.encrypt(password.encode()).decode()

    def decrypt_password(self, encrypted_password):
        f = Fernet(self.key)
        return f.decrypt(encrypted_password.encode()).decode()

    def add_password(self):
        website, ok1 = QInputDialog.getText(self, "Add Password", "Enter the website:")
        if ok1:
            username, ok2 = QInputDialog.getText(self, "Add Password", "Enter the username:")
            if ok2:
                password, ok3 = QInputDialog.getText(self, "Add Password", "Enter the password:", QLineEdit.EchoMode.Password)
                if ok3:
                    encrypted_password = self.encrypt_password(password)
                    self.passwords[website] = {
                        "username": username,
                        "password": encrypted_password,
                        "last_modified": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    self.update_password_tree()
                    self.save_passwords()

    def edit_password(self):
        selected = self.password_tree.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Error", "Please select a password to edit.")
            return

        website = selected[0].text(0)
        username, ok1 = QInputDialog.getText(self, "Edit Password", "Enter the new username:", text=self.passwords[website]["username"])
        if ok1:
            password, ok2 = QInputDialog.getText(self, "Edit Password", "Enter the new password:", QLineEdit.EchoMode.Password)
            if ok2:
                encrypted_password = self.encrypt_password(password)
                self.passwords[website] = {
                    "username": username,
                    "password": encrypted_password,
                    "last_modified": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                self.save_passwords()
                self.update_password_tree()
                QMessageBox.information(self, "Success", "Password updated successfully!")


    def delete_password(self):
        selected = self.password_tree.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Error", "Please select a password to delete.")
            return

        website = selected[0].text(0)
        confirm = QMessageBox.question(self, "Confirm Deletion", f"Are you sure you want to delete the password for {website}?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if confirm == QMessageBox.StandardButton.Yes:
            del self.passwords[website]
            self.save_passwords()
            self.update_password_tree()
            QMessageBox.information(self, "Success", "Password deleted successfully!")

    def copy_password(self):
        selected = self.password_tree.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Error", "Please select a password to copy.")
            return

        website = selected[0].text(0)
        password = self.decrypt_password(self.passwords[website]["password"])
        pyperclip.copy(password)
        QMessageBox.information(self, "Success", "Password copied to clipboard!")

    def generate_password(self):
        length = self.length_input.value()
        use_upper = self.use_uppercase.isChecked()
        use_lower = self.use_lowercase.isChecked()
        use_numbers = self.use_numbers.isChecked()
        use_symbols = self.use_symbols.isChecked()

        if not any([use_upper, use_lower, use_numbers, use_symbols]):
            QMessageBox.warning(self, "Error", "Please select at least one character type.")
            return

        char_set = ""
        if use_upper:
            char_set += string.ascii_uppercase
        if use_lower:
            char_set += string.ascii_lowercase
        if use_numbers:
            char_set += string.digits
        if use_symbols:
            char_set += string.punctuation

        password = ''.join(random.choice(char_set) for _ in range(length))
        self.password_display.setText(password)

    def copy_generated_password(self):
        password = self.password_display.text()
        if password:
            pyperclip.copy(password)
            QMessageBox.information(self, "Success", "Generated password copied to clipboard!")
        else:
            QMessageBox.warning(self, "Error", "No password generated yet.")

    def change_master_password(self):
        old_password, ok1 = QInputDialog.getText(self, "Change Master Password", "Enter your current master password:", QLineEdit.EchoMode.Password)
        if ok1:
            new_password, ok2 = QInputDialog.getText(self, "Change Master Password", "Enter your new master password:", QLineEdit.EchoMode.Password)
            if ok2:
                confirm_password, ok3 = QInputDialog.getText(self, "Change Master Password", "Confirm your new master password:", QLineEdit.EchoMode.Password)
                if ok3 and new_password == confirm_password:
                    # Verify old password
                    with open("master.key", "rb") as key_file:
                        file_content = key_file.read()
                        salt = file_content[:16]
                        stored_key = file_content[16:]

                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                    )
                    old_key = base64.urlsafe_b64encode(kdf.derive(old_password.encode()))

                    if old_key == stored_key:
                        # Generate new key
                        new_salt = os.urandom(16)
                        new_kdf = PBKDF2HMAC(
                            algorithm=hashes.SHA256(),
                            length=32,
                            salt=new_salt,
                            iterations=100000,
                        )
                        new_key = base64.urlsafe_b64encode(new_kdf.derive(new_password.encode()))

                        # Save new key
                        with open("master.key", "wb") as key_file:
                            key_file.write(new_salt + new_key)

                        self.key = new_key
                        self.re_encrypt_passwords(old_key, new_key)
                        QMessageBox.information(self, "Success", "Master password changed successfully!")
                    else:
                        QMessageBox.critical(self, "Error", "Incorrect current master password.")
                else:
                    QMessageBox.critical(self, "Error", "New passwords do not match or were not provided.")

    def re_encrypt_passwords(self, old_key, new_key):
        old_fernet = Fernet(old_key)
        new_fernet = Fernet(new_key)

        for website, data in self.passwords.items():
            decrypted_password = old_fernet.decrypt(data["password"].encode()).decode()
            encrypted_password = new_fernet.encrypt(decrypted_password.encode()).decode()
            self.passwords[website]["password"] = encrypted_password

        self.save_passwords()

    def export_passwords(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Passwords", "", "CSV Files (*.csv)")
        if file_path:
            with open(file_path, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Website", "Username", "Password", "Last Modified"])
                for website, data in self.passwords.items():
                    decrypted_password = self.decrypt_password(data["password"])
                    writer.writerow([website, data["username"], decrypted_password, data["last_modified"]])
            QMessageBox.information(self, "Success", "Passwords exported successfully!")

    def import_passwords(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Import Passwords", "", "CSV Files (*.csv)")
        if file_path:
            with open(file_path, 'r') as csvfile:
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
            self.update_password_tree()
            QMessageBox.information(self, "Success", "Passwords imported successfully!")

    def backup_passwords(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Backup Passwords", "", "JSON Files (*.json)")
        if file_path:
            with open(file_path, 'w') as f:
                json.dump(self.passwords, f)
            QMessageBox.information(self, "Success", "Passwords backed up successfully!")

    def restore_passwords(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Restore Passwords", "", "JSON Files (*.json)")
        if file_path:
            with open(file_path, 'r') as f:
                self.passwords = json.load(f)
            self.save_passwords()
            self.update_password_tree()
            QMessageBox.information(self, "Success", "Passwords restored successfully!")

    def toggle_dark_mode(self, is_dark):
        if is_dark:
            self.setStyleSheet("""
                QMainWindow, QWidget {
                    background-color: #121212;
                    color: #E0E0E0;
                }
                QLineEdit, QTreeWidget, QSpinBox {
                    background-color: #1E1E1E;
                    color: #E0E0E0;
                    border: 1px solid #333333;
                }
                QPushButton {
                    background-color: #0D47A1;
                    color: #FFFFFF;
                    border: none;
                    padding: 5px 10px;
                    border-radius: 3px;
                }
                QPushButton:hover {
                    background-color: #1565C0;
                }
                QTreeWidget::item:selected {
                    background-color: #2979FF;
                }
            """)
        else:
            self.apply_styles()

    def visit_website(self):
        import webbrowser
        webbrowser.open("https://www.linkedin.com/in/adnanalam04/")

    def load_passwords(self):
        try:
            with open("passwords.json", "r") as f:
                self.passwords = json.load(f)
        except FileNotFoundError:
            self.passwords = {}

    def save_passwords(self):
        with open("passwords.json", "w") as f:
            json.dump(self.passwords, f)

    def update_password_tree(self):
        self.password_tree.clear()
        for website, data in self.passwords.items():
            item = QTreeWidgetItem(self.password_tree)
            item.setText(0, website)
            item.setText(1, data['username'])
            item.setText(2, data.get('last_modified', 'N/A'))

    def search_passwords(self):
        search_term = self.search_bar.text().lower()
        self.password_tree.clear()
        for website, data in self.passwords.items():
            if search_term in website.lower() or search_term in data['username'].lower():
                item = QTreeWidgetItem(self.password_tree)
                item.setText(0, website)
                item.setText(1, data['username'])
                item.setText(2, data['last_modified'])

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CPSecurePassPro()
    window.show()
    sys.exit(app.exec())
