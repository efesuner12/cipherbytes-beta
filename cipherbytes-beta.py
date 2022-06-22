from Crypto import Random
from Crypto.Cipher import AES
import hashlib
import jks
import os
import sys
import platform
import getpass

from datetime import datetime
import string

from printy import inputy
from printy import printy
from termcolor import colored
import pyfiglet

class Printer:

    def print_intro(self):
        print(colored(pyfiglet.figlet_format("[CipherBytes] BETA -v1.0-"), "cyan"))
        print(colored("         Version: B-1.0 (2022) - Author: hackerman\n", "cyan"))

    def print_main_header(self):
        print()
        printy("--" * 35, "o")
        printy("MAIN MENU", "o")
        printy("--" * 35, "o")

    def print_file_enc_header(self):
        printy("--" * 35, "o")
        printy("AES-256 CBC FILE ENCRYPTION", "o")
        printy("--" * 35, "o")

    def print_file_dec_header(self):
        printy("--" * 35, "o")
        printy("AES-256 CBC FILE DECRYPTION", "o")
        printy("--" * 35, "o")

    def print_dir_enc_header(self):
        printy("--" * 35, "o")
        printy("AES-256 CBC DIRECTORY ENCRYPTION", "o")
        printy("--" * 35, "o")

    def print_dir_dec_header(self):
        printy("--" * 35, "o")
        printy("AES-256 CBC DIRECTORY DECRYPTION", "o")
        printy("--" * 35, "o")

    def print_text_enc_header(self):
        printy("--" * 35, "o")
        printy("AES-256 CBC TEXT ENCRYPTION", "o")
        printy("--" * 35, "o")

    def print_text_dec_header(self):
        printy("--" * 35, "o")
        printy("AES-256 CBC TEXT DECRYPTION", "o")
        printy("--" * 35, "o")
    
    def print_string_hash_header(self):
        printy("--" * 35, "o")
        printy("PBKDF2-SHA512 STRING HASH", "o")
        printy("--" * 35, "o")

    def print_jks_setup_header(self):
        printy("--" * 35, "o")
        printy("JAVA KEY STORE SETUP", "o")
        printy("--" * 35, "o")

class Validator:

    def valid_user_choice(self, choice):

        if choice.upper() == "QUIT":
            return True

        try:
            choice = int(choice)
            operator = Operation()

            return True if choice in operator.user_options else False
        except:
            return False

    def valid_enc_key_choice(self, choice):

        if choice.upper() == "QUIT":
            return True

        try:
            choice = int(choice)
            operator = Operation()

            return True if choice in operator.enc_key_options else False
        except:
            return False

    def valid_dec_key_choice(self, choice):

        if choice.upper() == "QUIT":
            return True

        try:
            choice = int(choice)
            operator = Operation()

            return True if choice in operator.dec_key_options else False
        except:
            return False

    def path_exists(self, path):

        if path.upper() == "QUIT":
            return True

        return True if os.path.exists(path) else False

    def valid_symmetric_key(self, key):
        
        if key.upper() == "QUIT":
            return True

        if len(key) == 64:
            return all(c in string.hexdigits for c in key)

    def dir_exists(self, dir_path):
        
        if dir_path.upper() == "QUIT":
            return True

        return True if os.path.isdir(dir_path) else False

    def ks_exists(self):
        ks_path = f"{os.path.expanduser('~')}/.cipherbytes-beta/{getpass.getuser()}-keystore"
        return True if os.path.exists(ks_path) else False

    def valid_password(self, password):

        if password.upper() == "QUIT":
            return True

        return False if " " in password else True

class Operation:

    user_options = [1, 2, 3, 4, 5, 6, 7]
    enc_key_options = [1, 2, 3]
    dec_key_options = [1, 2]

    def get_user_choice(self):
        printer = Printer()
        printer.print_main_header()

        return inputy(f"Please select one of the options below (Type QUIT to exit):\n1- AES-256 CBC File Encryption\n2- AES-256 CBC File Decryption\n3- AES-256 CBC Directory Encryption\n4- AES-256 CBC Directory Decryption\n5- AES-256 CBC String Encryption\n6- AES-256 CBC String Decryption\n7- PBKDF2-SHA512 Hash a String\n--> ", "o")

    def get_enc_key_choice(self):
        return inputy(f"Please select one of the options below (Type QUIT to exit):\n1- Use key in JKS\n2- Generate 256-bit key\n3- Use your own 256-bit hexadecimal key\n--> ", "o")

    def get_dec_key_choice(self):
        return inputy(f"Please select one of the options below (Type QUIT to exit):\n1- Use key in JKS\n2- Insert 256-bit hexadecimal key\n--> ", "o")

class Cryptographic_Key:

    def __init__(self):
        self.owner = getpass.getuser()
        self.store_dir = f"{os.path.expanduser('~')}/.cipherbytes-beta/"
        self.store_name = f"{self.owner}-keystore"

    def generate_ks_key(self, password):
        try:
            if not os.path.isdir(self.store_dir):
                print(colored(f"Does not exists -- {self.store_dir}", "magenta"))
                os.mkdir(self.store_dir)
                print(colored(f"Directory generated!", "magenta"))
            
            os.system(f"keytool -genseckey -alias {self.owner} -keypass {password} -keyalg AES -keysize 256 -keystore {self.store_dir + self.store_name} -storepass {password} -storetype jceks")
            
            return True
        except Exception as e:
            print(colored(f"There has been an error while generating the JKS key! Please try again.", "red"))
            print(colored(f"Caught Error: {e}\n", "red"))
            return False

    def get_ks_key(self, store_password, key_password):
        key_store = jks.KeyStore.load(self.store_dir + self.store_name, store_password)
        key_entry = key_store.secret_keys[self.owner]

        if not key_entry.is_decrypted():
            key_entry.decrypt(key_password)

        return key_entry.key

    def generate_key(self):
        return os.urandom(32).hex()

    def convert_key(self, hex_key):
        return bytes.fromhex(hex_key)

class Cryptography:

    def pad(self, data):
        return data + b"\0" * (AES.block_size - len(data) % AES.block_size)

    def encrypt(self, data, key):
        data = self.pad(data)
        iv = Random.new().read(AES.block_size)
        enc = AES.new(key, AES.MODE_CBC, iv)

        return iv + enc.encrypt(data)

    def encrypt_file(self, file_name, key):

        with open(file_name, "rb") as f:
            data = f.read()

        ciphertext = self.encrypt(data, key)

        new_file_name = file_name + ".enc"

        with open(new_file_name, "wb") as f:
            f.write(ciphertext)
        
        os.remove(file_name)

        return new_file_name

    def encrypt_dir(self, dir_path, key):
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                file = root + "/" + file
                path, ext = os.path.splitext(file)

                if not ext == ".enc":
                    print(colored(f"Encrypting {file}", "magenta"))
                    self.encrypt_file(file, key)
        print()

    def encrypt_text(self, data, key):
        data = bytes(data.encode("utf-8"))
        ciphertext = self.encrypt(data, key)

        return ciphertext.hex()

    def decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        dec = AES.new(key, AES.MODE_CBC, iv)
        plaintext = dec.decrypt(ciphertext[AES.block_size:])

        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name, key):

        with open(file_name, "rb") as f:
            data = f.read()
        
        plaintext = self.decrypt(data, key)

        new_file_name = file_name[:-4]

        with open(new_file_name, "wb") as f:
            f.write(plaintext)

        os.remove(file_name)

        return new_file_name

    def decrypt_dir(self, dir_path, key):
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                file = root + "/" + file
                path, ext = os.path.splitext(file)

                if ext == ".enc":
                    print(colored(f"Decrypting {file}", "magenta"))
                    self.decrypt_file(file, key)

    def decrypt_text(self, data, key):
        data = bytes.fromhex(data)
        return self.decrypt(data, key).decode("utf-8")

    def hash(self, data):
        salt = os.urandom(16)
        iteration_num = 100000
        dt_hash = hashlib.pbkdf2_hmac('sha512', data.encode("utf-8"), salt, iteration_num)

        enc = salt + dt_hash

        return (salt.hex(), iteration_num, enc.hex())


if __name__ == "__main__":
    os.system("cls||clear")
    
    printer = Printer()
    printer.print_intro()

    choice = "0"

    while choice.upper() != "QUIT":
        operator = Operation()
        choice = operator.get_user_choice()

        validator = Validator()
        valid_choice = validator.valid_user_choice(choice)

        if choice.upper() == "QUIT":
            break

        while not valid_choice:
            print(colored("\nPlease enter a valid option!", "red"))
            choice = operator.get_user_choice()
            valid_choice = validator.valid_user_choice(choice)
        
        cryptographic_key = Cryptographic_Key()
        crypto = Cryptography()

        ## AES-256 CBC File Encryption:
        ##
        if choice == "1":
            print()
            printer.print_file_enc_header()

            path = "0"

            while path.upper() != "QUIT":
                path = inputy("Please enter the file path (Type QUIT to exit): ", "o")
                valid_path = validator.path_exists(path)
                
                while not valid_path:
                    print(colored("Please enter a valid or existing file path!\n", "red"))
                    path = inputy("Please enter the file path (Type QUIT to exit): ", "o")
                    valid_path = validator.path_exists(path)

                if path.upper() == "QUIT":
                    print()
                    break
                
                print()
                enc_key_choice = "0"

                while enc_key_choice.upper() != "QUIT":
                    enc_key_choice = operator.get_enc_key_choice()
                    valid_key_choice = validator.valid_enc_key_choice(enc_key_choice)

                    while not valid_key_choice:
                        print(colored("Please enter a valid option!\n", "red"))
                        enc_key_choice = operator.get_enc_key_choice()
                        valid_key_choice = validator.valid_enc_key_choice(enc_key_choice)

                    if enc_key_choice.upper() == "QUIT":
                        print()
                        break

                    symmetric_key_exists = False

                    ## JKS:
                    ##
                    if enc_key_choice == "1":
                        if validator.ks_exists():
                            store_password = "0"

                            while store_password.upper() != "QUIT":
                                store_password = inputy("\nPlease enter your JKS password (Type QUIT to exit):\n--> ", "o")
                                valid_store_password_input = validator.valid_password(store_password)

                                while not valid_store_password_input:
                                    print(colored("Please enter a valid password!", "red"))
                                    store_password = inputy("\nPlease enter your JKS password (Type QUIT to exit):\n--> ", "o")
                                    valid_store_password_input = validator.valid_password(store_password)

                                if store_password.upper() == "QUIT":
                                    print()
                                    break

                                try:
                                    symmetric_key = cryptographic_key.get_ks_key(store_password, store_password)
                                    symmetric_key_exists = True

                                    print(colored(f"\nKey Store Path: {cryptographic_key.store_dir + cryptographic_key.store_name}\n", "magenta"))
                                    break
                                except Exception as e:
                                    print(colored(f"There has been an error while getting the JKS key! Please check your password.", "red"))
                                    print(colored(f"Caught Error: {e}\n", "red"))
                                    break
                        else:
                            print(colored("No JKS has been found!\n", "red"))
                            printer.print_jks_setup_header()

                            store_password = "0"

                            while store_password.upper() != "QUIT":
                                store_password = inputy("Please enter JKS password (Type QUIT to exit):\n--> ", "o")
                                valid_store_password_input = validator.valid_password(store_password)

                                while not valid_store_password_input:
                                    print(colored("Please enter a valid password!", "red"))
                                    store_password = inputy("\nPlease enter JKS password (Type QUIT to exit):\n--> ", "o")
                                    valid_store_password_input = validator.valid_password(store_password)

                                if store_password.upper() == "QUIT":
                                    print()
                                    break

                                try:
                                    if cryptographic_key.generate_ks_key(store_password):
                                        symmetric_key = cryptographic_key.get_ks_key(store_password, store_password)
                                        symmetric_key_exists = True

                                        print(colored(f"\nKey Store Path: {cryptographic_key.store_dir + cryptographic_key.store_name}\n", "magenta"))
                                        break
                                except Exception as e:
                                    print(colored(f"There has been an error while generating the JKS key! Please try again.", "red"))
                                    print(colored(f"Caught Error: {e}\n", "red"))
                                    break
                    ## Generate Key:
                    ##
                    elif enc_key_choice == "2":
                        hex_symmetric_key = cryptographic_key.generate_key()

                        print(colored(f"\nSYMMETRIC KEY: {hex_symmetric_key}", "magenta"))
                        print(colored("Please safely store this key since it will be asked when decrypting your files.", "red"))
                        print(colored("Do not share this key with anyone!\n", "red"))

                        symmetric_key = cryptographic_key.convert_key(hex_symmetric_key)
                        symmetric_key_exists = True
                    ## Own Key:
                    ##
                    elif enc_key_choice == "3":
                        hex_symmetric_key = inputy("\nPlease enter your symmetric key in hexadecimal (Type QUIT to exit): ", "o")
                        valid_key = validator.valid_symmetric_key(hex_symmetric_key)
    
                        while not valid_key:
                            print(colored("Please enter a valid symmetric key!\nMake sure it's in hexadecimal.", "red"))
                            hex_symmetric_key = inputy("\nPlease enter your symmetric key in hexadecimal (Type QUIT to exit): ", "o")
                            valid_key = validator.valid_symmetric_key(hex_symmetric_key)

                        if hex_symmetric_key.upper() == "QUIT":
                            print()
                            break
                        
                        symmetric_key = cryptographic_key.convert_key(hex_symmetric_key)
                        symmetric_key_exists = True
                        print()

                    if symmetric_key_exists:
                        saved_path = crypto.encrypt_file(path, symmetric_key)
                        print(colored("Encryption successfully compeleted!", "magenta"))
                        print(colored(f"Saved to: {saved_path}", "magenta"))
                        print()

                        break
        ## AES-256 CBC File Decryption:
        ##
        elif choice == "2":
            print()
            printer.print_file_dec_header()

            path = "0"

            while path.upper() != "QUIT":
                path = inputy("Please enter the file path (Type QUIT to exit): ", "o")
                valid_path = validator.path_exists(path)
                
                while not valid_path:
                    print(colored("Please enter a valid or existing file path!\n", "red"))
                    path = inputy("Please enter the file path (Type QUIT to exit): ", "o")
                    valid_path = validator.path_exists(path)

                if path.upper() == "QUIT":
                    break
                
                print()
                dec_key_choice = "0"

                while dec_key_choice.upper() != "QUIT":
                    dec_key_choice = operator.get_dec_key_choice()
                    valid_key_choice = validator.valid_dec_key_choice(dec_key_choice)

                    while not valid_key_choice:
                        print(colored("Please enter a valid option!\n", "red"))
                        dec_key_choice = operator.get_dec_key_choice()
                        valid_key_choice = validator.valid_dec_key_choice(dec_key_choice)

                    if dec_key_choice.upper() == "QUIT":
                        print()
                        break

                    symmetric_key_exists = False

                    ## JKS:
                    ##
                    if dec_key_choice == "1":
                        if validator.ks_exists():
                            store_password = "0"

                            while store_password.upper() != "QUIT":
                                store_password = inputy("\nPlease enter your JKS password (Type QUIT to exit):\n--> ", "o")
                                valid_store_password_input = validator.valid_password(store_password)

                                while not valid_store_password_input:
                                    print(colored("Please enter a valid password!", "red"))
                                    store_password = inputy("\nPlease enter your JKS password (Type QUIT to exit):\n--> ", "o")
                                    valid_store_password_input = validator.valid_password(store_password)

                                if store_password.upper() == "QUIT":
                                    print()
                                    break

                                try:
                                    symmetric_key = cryptographic_key.get_ks_key(store_password, store_password)
                                    symmetric_key_exists = True

                                    print(colored(f"\nKey Store Path: {cryptographic_key.store_dir + cryptographic_key.store_name}\n", "magenta"))
                                    break
                                except Exception as e:
                                    print(colored(f"There has been an error while getting the JKS key! Please check your password.", "red"))
                                    print(colored(f"Caught Error: {e}\n", "red"))
                                    break
                        else:
                            print(colored("No JKS has been found!", "red"))
                            print(colored("You can setup JKS in any encryption option.\n", "red"))
                    ## Insert key:
                    ##
                    elif dec_key_choice == "2":
                        hex_symmetric_key = "0"

                        while hex_symmetric_key.upper() != "QUIT":
                            hex_symmetric_key = inputy("\nPlease enter your hexadecimal symmetric key (Type QUIT to exit): ", "o")
                            valid_key = validator.valid_symmetric_key(hex_symmetric_key)
        
                            while not valid_key:
                                print(colored("Please enter a valid symmetric key!", "red"))
                                hex_symmetric_key = inputy("\nPlease enter your hexadecimal symmetric key (Type QUIT to exit): ", "o")
                                valid_key = validator.valid_symmetric_key(hex_symmetric_key)

                            if hex_symmetric_key.upper() == "QUIT":
                                print()
                                break
                            
                            symmetric_key = cryptographic_key.convert_key(hex_symmetric_key)
                            symmetric_key_exists = True
                            break

                    if symmetric_key_exists:
                        saved_path = crypto.decrypt_file(path, symmetric_key)
                        print(colored("\nDecryption successfully compeleted!", "magenta"))
                        print(colored(f"Saved to: {saved_path}", "magenta"))
                        print()

                        break
        ## AES-256 CBC Directory Encryption:
        ##
        elif choice == "3":
            print()
            printer.print_dir_enc_header()

            dir_path = "0"

            while dir_path.upper() != "QUIT":
                dir_path = inputy("Please enter the directory path (Type QUIT to exit): ", "o")
                valid_dir_path = validator.dir_exists(dir_path)
                
                while not valid_dir_path:
                    print(colored("Please enter a valid or existing directory path!\n", "red"))
                    dir_path = inputy("Please enter the directory path (Type QUIT to exit): ", "o")
                    valid_dir_path = validator.dir_exists(dir_path)

                if dir_path.upper() == "QUIT":
                    print()
                    break
                
                print()
                enc_key_choice = "0"

                while enc_key_choice.upper() != "QUIT":
                    enc_key_choice = operator.get_enc_key_choice()
                    valid_key_choice = validator.valid_enc_key_choice(enc_key_choice)

                    while not valid_key_choice:
                        print(colored("Please enter a valid option!\n", "red"))
                        enc_key_choice = operator.get_enc_key_choice()
                        valid_key_choice = validator.valid_enc_key_choice(enc_key_choice)

                    if enc_key_choice.upper() == "QUIT":
                        print()
                        break

                    symmetric_key_exists = False

                    ## JKS:
                    ##
                    if enc_key_choice == "1":
                        if validator.ks_exists():
                            store_password = "0"

                            while store_password.upper() != "QUIT":
                                store_password = inputy("\nPlease enter your JKS password (Type QUIT to exit):\n--> ", "o")
                                valid_store_password_input = validator.valid_password(store_password)

                                while not valid_store_password_input:
                                    print(colored("Please enter a valid password!", "red"))
                                    store_password = inputy("\nPlease enter your JKS password (Type QUIT to exit):\n--> ", "o")
                                    valid_store_password_input = validator.valid_password(store_password)

                                if store_password.upper() == "QUIT":
                                    print()
                                    break

                                try:
                                    symmetric_key = cryptographic_key.get_ks_key(store_password, store_password)
                                    symmetric_key_exists = True

                                    print(colored(f"\nKey Store Path: {cryptographic_key.store_dir + cryptographic_key.store_name}\n", "magenta"))
                                    break
                                except Exception as e:
                                    print(colored(f"There has been an error while getting the JKS key! Please check your password.", "red"))
                                    print(colored(f"Caught Error: {e}\n", "red"))
                                    break
                        else:
                            print(colored("No JKS has been found!\n", "red"))
                            printer.print_jks_setup_header()

                            store_password = "0"

                            while store_password.upper() != "QUIT":
                                store_password = inputy("Please enter JKS password (Type QUIT to exit):\n--> ", "o")
                                valid_store_password_input = validator.valid_password(store_password)

                                while not valid_store_password_input:
                                    print(colored("Please enter a valid password!", "red"))
                                    store_password = inputy("\nPlease enter JKS password (Type QUIT to exit):\n--> ", "o")
                                    valid_store_password_input = validator.valid_password(store_password)

                                if store_password.upper() == "QUIT":
                                    print()
                                    break

                                try:
                                    if cryptographic_key.generate_ks_key(store_password):
                                        symmetric_key = cryptographic_key.get_ks_key(store_password, store_password)
                                        symmetric_key_exists = True

                                        print(colored(f"\nKey Store Path: {cryptographic_key.store_dir + cryptographic_key.store_name}\n", "magenta"))
                                        break
                                except Exception as e:
                                    print(colored(f"There has been an error while generating the JKS key! Please try again.", "red"))
                                    print(colored(f"Caught Error: {e}\n", "red"))
                                    break
                    ## Generate Key:
                    ##
                    elif enc_key_choice == "2":
                        hex_symmetric_key = cryptographic_key.generate_key()

                        print(colored(f"\nSYMMETRIC KEY: {hex_symmetric_key}", "magenta"))
                        print(colored("Please safely store this key since it will be asked when decrypting your files.", "red"))
                        print(colored("Do not share this key with anyone!\n", "red"))

                        symmetric_key = cryptographic_key.convert_key(hex_symmetric_key)
                        symmetric_key_exists = True
                    ## Own Key:
                    ##
                    elif enc_key_choice == "3":
                        hex_symmetric_key = inputy("\nPlease enter your symmetric key in hexadecimal (Type QUIT to exit): ", "o")
                        valid_key = validator.valid_symmetric_key(hex_symmetric_key)
    
                        while not valid_key:
                            print(colored("Please enter a valid symmetric key!\nMake sure it's in hexadecimal.", "red"))
                            hex_symmetric_key = inputy("\nPlease enter your symmetric key in hexadecimal (Type QUIT to exit): ", "o")
                            valid_key = validator.valid_symmetric_key(hex_symmetric_key)

                        if hex_symmetric_key.upper() == "QUIT":
                            print()
                            break
                        
                        symmetric_key = cryptographic_key.convert_key(hex_symmetric_key)
                        symmetric_key_exists = True
                        print()

                    if symmetric_key_exists:
                        start_time = datetime.now()
                        crypto.encrypt_dir(dir_path, symmetric_key)
                        ending_time = datetime.now()

                        process_time = ending_time - start_time

                        start_time = start_time.strftime("%H:%M:%S")
                        ending_time = ending_time.strftime("%H:%M:%S")

                        print(colored("Encryption successfully compeleted!", "magenta"))
                        print(colored(f"Start time: {start_time}\nEnding time: {ending_time}\nTime took to complete: {process_time}", "magenta"))
                        print()

                        break
        ## AES-256 CBC Directory Decryption:
        ##
        elif choice == "4":
            print()
            printer.print_dir_dec_header()

            dir_path = "0"

            while dir_path.upper() != "QUIT":
                dir_path = inputy("Please enter the directory path (Type QUIT to exit): ", "o")
                valid_dir_path = validator.dir_exists(dir_path)
                
                while not valid_dir_path:
                    print(colored("Please enter a valid or existing directory path!\n", "red"))
                    dir_path = inputy("Please enter the directory path (Type QUIT to exit): ", "o")
                    valid_dir_path = validator.dir_exists(dir_path)

                if dir_path.upper() == "QUIT":
                    print()
                    break

                print()
                dec_key_choice = "0"

                while dec_key_choice.upper() != "QUIT":
                    dec_key_choice = operator.get_dec_key_choice()
                    valid_key_choice = validator.valid_dec_key_choice(dec_key_choice)

                    while not valid_key_choice:
                        print(colored("Please enter a valid option!\n", "red"))
                        dec_key_choice = operator.get_dec_key_choice()
                        valid_key_choice = validator.valid_dec_key_choice(dec_key_choice)

                    if dec_key_choice.upper() == "QUIT":
                        print()
                        break

                    symmetric_key_exists = False

                    ## JKS:
                    ##
                    if dec_key_choice == "1":
                        if validator.ks_exists():
                            store_password = "0"

                            while store_password.upper() != "QUIT":
                                store_password = inputy("\nPlease enter your JKS password (Type QUIT to exit):\n--> ", "o")
                                valid_store_password_input = validator.valid_password(store_password)

                                while not valid_store_password_input:
                                    print(colored("Please enter a valid password!", "red"))
                                    store_password = inputy("\nPlease enter your JKS password (Type QUIT to exit):\n--> ", "o")
                                    valid_store_password_input = validator.valid_password(store_password)

                                if store_password.upper() == "QUIT":
                                    print()
                                    break

                                try:
                                    symmetric_key = cryptographic_key.get_ks_key(store_password, store_password)
                                    symmetric_key_exists = True

                                    print(colored(f"\nKey Store Path: {cryptographic_key.store_dir + cryptographic_key.store_name}\n", "magenta"))
                                    break
                                except Exception as e:
                                    print(colored(f"There has been an error while getting the JKS key! Please check your password.", "red"))
                                    print(colored(f"Caught Error: {e}\n", "red"))
                                    break
                        else:
                            print(colored("No JKS has been found!", "red"))
                            print(colored("You can setup JKS in any encryption option.\n", "red"))
                    ## Insert key:
                    ##
                    elif dec_key_choice == "2":
                        hex_symmetric_key = "0"

                        while hex_symmetric_key.upper() != "QUIT":
                            hex_symmetric_key = inputy("\nPlease enter your hexadecimal symmetric key (Type QUIT to exit): ", "o")
                            valid_key = validator.valid_symmetric_key(hex_symmetric_key)
        
                            while not valid_key:
                                print(colored("Please enter a valid symmetric key!", "red"))
                                hex_symmetric_key = inputy("\nPlease enter your hexadecimal symmetric key (Type QUIT to exit): ", "o")
                                valid_key = validator.valid_symmetric_key(hex_symmetric_key)

                            if hex_symmetric_key.upper() == "QUIT":
                                print()
                                break
                            
                            symmetric_key = cryptographic_key.convert_key(hex_symmetric_key)
                            symmetric_key_exists = True
                            break

                    if symmetric_key_exists:
                        start_time = datetime.now()
                        crypto.decrypt_dir(dir_path, symmetric_key)
                        ending_time = datetime.now()

                        process_time = ending_time - start_time

                        start_time = start_time.strftime("%H:%M:%S")
                        ending_time = ending_time.strftime("%H:%M:%S")

                        print(colored("\nDecryption successfully compeleted!", "magenta"))
                        print(colored(f"Start time: {start_time}\nEnding time: {ending_time}\nTime took to complete: {process_time}", "magenta"))
                        print()

                        break
        ## AES-256 CBC String Encryption:
        ##
        elif choice == "5":
            print()
            printer.print_text_enc_header()

            plaintext = "0"

            while plaintext.upper() != "QUIT":
                plaintext = inputy("Please enter the text (Type QUIT to exit): ", "o")

                if plaintext.upper() == "QUIT":
                    break
                
                print()
                enc_key_choice = "0"

                while enc_key_choice.upper() != "QUIT":
                    enc_key_choice = operator.get_enc_key_choice()
                    valid_key_choice = validator.valid_enc_key_choice(enc_key_choice)

                    while not valid_key_choice:
                        print(colored("Please enter a valid option!\n", "red"))
                        enc_key_choice = operator.get_enc_key_choice()
                        valid_key_choice = validator.valid_enc_key_choice(enc_key_choice)

                    if enc_key_choice.upper() == "QUIT":
                        print()
                        break

                    symmetric_key_exists = False

                    ## JKS:
                    ##
                    if enc_key_choice == "1":
                        if validator.ks_exists():
                            store_password = "0"

                            while store_password.upper() != "QUIT":
                                store_password = inputy("\nPlease enter your JKS password (Type QUIT to exit):\n--> ", "o")
                                valid_store_password_input = validator.valid_password(store_password)

                                while not valid_store_password_input:
                                    print(colored("Please enter a valid password!", "red"))
                                    store_password = inputy("\nPlease enter your JKS password (Type QUIT to exit):\n--> ", "o")
                                    valid_store_password_input = validator.valid_password(store_password)

                                if store_password.upper() == "QUIT":
                                    print()
                                    break

                                try:
                                    symmetric_key = cryptographic_key.get_ks_key(store_password, store_password)
                                    symmetric_key_exists = True

                                    print(colored(f"\nKey Store Path: {cryptographic_key.store_dir + cryptographic_key.store_name}\n", "magenta"))
                                    break
                                except Exception as e:
                                    print(colored(f"There has been an error while getting the JKS key! Please check your password.", "red"))
                                    print(colored(f"Caught Error: {e}\n", "red"))
                                    break
                        else:
                            print(colored("No JKS has been found!\n", "red"))
                            printer.print_jks_setup_header()

                            store_password = "0"

                            while store_password.upper() != "QUIT":
                                store_password = inputy("Please enter JKS password (Type QUIT to exit):\n--> ", "o")
                                valid_store_password_input = validator.valid_password(store_password)

                                while not valid_store_password_input:
                                    print(colored("Please enter a valid password!", "red"))
                                    store_password = inputy("\nPlease enter JKS password (Type QUIT to exit):\n--> ", "o")
                                    valid_store_password_input = validator.valid_password(store_password)

                                if store_password.upper() == "QUIT":
                                    print()
                                    break

                                try:
                                    if cryptographic_key.generate_ks_key(store_password):
                                        symmetric_key = cryptographic_key.get_ks_key(store_password, store_password)
                                        symmetric_key_exists = True

                                        print(colored(f"\nKey Store Path: {cryptographic_key.store_dir + cryptographic_key.store_name}\n", "magenta"))
                                        break
                                except Exception as e:
                                    print(colored(f"There has been an error while generating the JKS key! Please try again.", "red"))
                                    print(colored(f"Caught Error: {e}\n", "red"))
                                    break
                    ## Generate Key:
                    ##
                    elif enc_key_choice == "2":
                        hex_symmetric_key = cryptographic_key.generate_key()

                        print(colored(f"\nSYMMETRIC KEY: {hex_symmetric_key}", "magenta"))
                        print(colored("Please safely store this key since it will be asked when decrypting your files.", "red"))
                        print(colored("Do not share this key with anyone!\n", "red"))

                        symmetric_key = cryptographic_key.convert_key(hex_symmetric_key)
                        symmetric_key_exists = True
                    ## Own Key:
                    ##
                    elif enc_key_choice == "3":
                        hex_symmetric_key = inputy("\nPlease enter your symmetric key in hexadecimal (Type QUIT to exit): ", "o")
                        valid_key = validator.valid_symmetric_key(hex_symmetric_key)
    
                        while not valid_key:
                            print(colored("Please enter a valid symmetric key!\nMake sure it's in hexadecimal.", "red"))
                            hex_symmetric_key = inputy("\nPlease enter your symmetric key in hexadecimal (Type QUIT to exit): ", "o")
                            valid_key = validator.valid_symmetric_key(hex_symmetric_key)

                        if hex_symmetric_key.upper() == "QUIT":
                            print()
                            break
                        
                        symmetric_key = cryptographic_key.convert_key(hex_symmetric_key)
                        symmetric_key_exists = True
                        print()

                    if symmetric_key_exists:
                        ciphertext = crypto.encrypt_text(plaintext, symmetric_key)
                        print(colored(f"Cipher Text: {ciphertext}", "magenta"))
                        print(colored("Encryption successfully compeleted!", "magenta"))
                        print()

                        break
        ## AES-256 CBC String Decryption:
        ##
        elif choice == "6":
            print()
            printer.print_text_dec_header()

            ciphertext = "0"

            while ciphertext.upper() != "QUIT":
                ciphertext = inputy("Please enter the ciphertext (Type QUIT to exit): ", "o")

                if ciphertext.upper() == "QUIT":
                    break

                print()
                dec_key_choice = "0"

                while dec_key_choice.upper() != "QUIT":
                    dec_key_choice = operator.get_dec_key_choice()
                    valid_key_choice = validator.valid_dec_key_choice(dec_key_choice)

                    while not valid_key_choice:
                        print(colored("Please enter a valid option!\n", "red"))
                        dec_key_choice = operator.get_dec_key_choice()
                        valid_key_choice = validator.valid_dec_key_choice(dec_key_choice)

                    if dec_key_choice.upper() == "QUIT":
                        print()
                        break

                    symmetric_key_exists = False

                    ## JKS:
                    ##
                    if dec_key_choice == "1":
                        if validator.ks_exists():
                            store_password = "0"

                            while store_password.upper() != "QUIT":
                                store_password = inputy("\nPlease enter your JKS password (Type QUIT to exit):\n--> ", "o")
                                valid_store_password_input = validator.valid_password(store_password)

                                while not valid_store_password_input:
                                    print(colored("Please enter a valid password!", "red"))
                                    store_password = inputy("\nPlease enter your JKS password (Type QUIT to exit):\n--> ", "o")
                                    valid_store_password_input = validator.valid_password(store_password)

                                if store_password.upper() == "QUIT":
                                    print()
                                    break

                                try:
                                    symmetric_key = cryptographic_key.get_ks_key(store_password, store_password)
                                    symmetric_key_exists = True

                                    print(colored(f"\nKey Store Path: {cryptographic_key.store_dir + cryptographic_key.store_name}\n", "magenta"))
                                    break
                                except Exception as e:
                                    print(colored(f"There has been an error while getting the JKS key! Please check your password.", "red"))
                                    print(colored(f"Caught Error: {e}\n", "red"))
                                    break
                        else:
                            print(colored("No JKS has been found!", "red"))
                            print(colored("You can setup JKS in any encryption option.\n", "red"))
                    ## Insert key:
                    ##
                    elif dec_key_choice == "2":
                        hex_symmetric_key = "0"

                        while hex_symmetric_key.upper() != "QUIT":
                            hex_symmetric_key = inputy("\nPlease enter your hexadecimal symmetric key (Type QUIT to exit): ", "o")
                            valid_key = validator.valid_symmetric_key(hex_symmetric_key)
        
                            while not valid_key:
                                print(colored("Please enter a valid symmetric key!", "red"))
                                hex_symmetric_key = inputy("\nPlease enter your hexadecimal symmetric key (Type QUIT to exit): ", "o")
                                valid_key = validator.valid_symmetric_key(hex_symmetric_key)

                            if hex_symmetric_key.upper() == "QUIT":
                                print()
                                break
                            
                            symmetric_key = cryptographic_key.convert_key(hex_symmetric_key)
                            symmetric_key_exists = True
                            break

                    if symmetric_key_exists:
                        plaintext = crypto.decrypt_text(ciphertext, symmetric_key)
                        print(colored(f"\nPlain Text: {plaintext}", "magenta"))
                        print(colored("Decryption successfully compeleted!", "magenta"))
                        print()

                        break
        ## PBKDF2-SHA512 Hash a String:
        ##
        elif choice == "7":
            print()
            printer.print_string_hash_header()

            string = "0"

            while string.upper() != "QUIT":
                string = inputy("Please enter the string (Type QUIT to exit): ", "o")

                if string.upper() == "QUIT":
                    break

                salt, iteration, hashed_string = crypto.hash(string)
                print(colored(f"\nHashed String: {hashed_string}", "magenta"))
                print(colored(f"\nSalt: {salt}\nNumber of iterations: {iteration}\n", "magenta"))
                print(colored("Successfully Hashed!", "magenta"))
                print()

    printy("\nBYE!", "o")
    sys.exit(0)
