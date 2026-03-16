# Java Password Manager

A console-based Password Manager built in Java that allows users to securely store and manage account credentials.  
The application uses **AES encryption** to protect saved passwords and includes a **master password system** for added security.

## Features
- Securely add and store password entries
- Automatic saving after adding new entries
- View all stored credentials in the console
- Update existing account information
- Delete saved entries
- Change the master password when needed
- AES encryption for protecting sensitive data
- Simple and user-friendly menu-driven interface


## Project Structure
This project is organized into 3 main classes:

- `AES`  
  Handles encryption and decryption of stored passwords using AES.

- `PasswordEntry`  
  Represents a password record, such as website/app name, username, and password.

- `PasswordManager`  
  Main application logic, menu system, and password management operations.

## Technologies Used
- Java
- NetBeans IDE
- Object-Oriented Programming (OOP)
- AES Encryption
- File handling / data persistence
- Java Collections

## How It Works
When the program starts, the user interacts with a console-based menu that allows them to manage stored credentials.

Available options include:
1. Add a new password entry
2. View saved entries
3. Delete an entry
4. Update an entry
5. Change the master password
6. Exit the application

Passwords are encrypted before storage using AES to improve security.

## Purpose of the Project
This project was developed to practice and demonstrate:
- Java programming fundamentals
- Object-oriented design
- Secure password handling concepts
- Encryption and decryption using AES
- Console application development
- Data management and file operations

## Screenshots
<h2>Screenshots</h2>

<h3>Main Menu</h3>
<img src="Options Screenshot.png" width="600">

<h3>Testing Password Stored</h3>
<img src="Storing the Master Password.png" width="600">


## Author
Zeina Muhammed
