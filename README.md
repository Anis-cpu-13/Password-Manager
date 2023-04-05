# Password-Manager

This is a simple password manager that uses AES encryption to store and manage passwords. The program allows users to add, edit, delete, list, and show passwords.

## Requirements

This program requires the following packages:

    click
    pycryptodome

You can install them using pip:


    pip install click pycryptodome

## Usage

To use the password manager, simply run the following command:

python password_manager.py

This will start the command-line interface of the password manager. The program provides the following commands:

        add: Adds a new password.
        edit: Edits an existing password.
        delete: Deletes an existing password.
        list: Lists all stored passwords.
        show: Shows the details of a specific password.

Each command has its own set of options that you can access by running the command with the --help option. For example:

    python password_manager.py add --help

## Security

The password manager uses AES encryption to protect the passwords. The encryption key is generated from a user-provided master password using a SHA-256 hash function.
