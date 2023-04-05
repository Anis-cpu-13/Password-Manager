
import click
import os
import json
import hashlib
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Cryptodome.Cipher import AES
from base64 import b64encode, b64decode
from types import SimpleNamespace

def generate_key(seed):
    m = hashlib.sha256()
    m.update(bytes(seed, "utf-8"))
    return m.digest()[16:]

def prompt_master_password():   
    password = input("master password :")
    password_save = password 
    return generate_key(password_save)


class Vault:
    def __init__(self, username_list, password_list, website_list):
        self.username_list = username_list
        self.password_list = password_list
        self.website_list = website_list


    def marshal(self):
        return json.dumps(self, default=lambda o: o.__dict__,
                sort_keys=True, indent=4)


    def unmarshal(data):
        return json.loads(data, object_hook=lambda d: SimpleNamespace(**d))


    def encrypt(self, key):
        data = self.marshal()
        cipher = AES.new(key, AES.MODE_CBC)
        iv = b64encode(cipher.iv).decode('utf-8')
        enc = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
        enc = b64encode(enc).decode('utf-8')
        return f"{iv}:{enc}"


    def decrypt(key, enc):
        iv, data = enc.split(":")
        iv = b64decode(iv)
        data = b64decode(data)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        dec = unpad(cipher.decrypt(data), AES.block_size).decode()
        return dec


    def add(vault, username, password, website):
        vault.username_list.append(username)
        vault.password_list.append(password)
        vault.website_list.append(website)

    def edit(vault, id, username, password, website):
        vault.username_list[id] = username
        vault.password_list[id] = password
        vault.website_list[id] = website    

    def delete(vault, id):
         del vault.username_list[id]
         del vault.password_list[id]
         del vault.website_list[id]
    
    def save(enc_data):
        if os.path.isfile("./vault.txt"):
            os.remove("./vault.txt")
        file = open("./vault.txt", "wb")
        file.write(bytes(enc_data, "utf-8"))


    def load():
        if os.path.isfile("./vault.txt"):
            file = open("./vault.txt", "rb")
            enc_data = file.read()
            return enc_data
        return None



@click.group()
def cli():
    pass


@cli.command('add')
@click.option('--username', prompt='username', required=True)
@click.option('--password', prompt='password', required=True,
              hide_input=True)
@click.option('--website', prompt='website', required=True)
def add(username, password, website):
    enc_data = Vault.load()
    if enc_data != None:
        dec = Vault.decrypt(key, enc_data.decode('utf-8'))
        tmp = Vault.unmarshal(dec)
        new = Vault(
            tmp.username_list,
            tmp.password_list,
            tmp.website_list
        )
    else:
        new = Vault([], [], [])
    Vault.add(
        new,
        username,
        password,
        website
    )
    new_enc = new.encrypt(key)
    Vault.save(new_enc)

@cli.command('edit')
@click.option('--username', prompt='username', required=True)
@click.option('--password', prompt='password', required=True,
              hide_input=True)
@click.option('--website', prompt='website', required=True)
@click.option('--id', prompt=False, required=True)
def edit(id, username, password, website):
    enc_data = Vault.load()
    dec = Vault.decrypt(key, enc_data.decode('utf-8'))
    tmp = Vault.unmarshal(dec)
    new = Vault(
            tmp.username_list,
            tmp.password_list,
            tmp.website_list
        )

    id = int(id)
    Vault.edit(new,
        id,
        username,
        password,
        website
        )
    new_enc = new.encrypt(key)
    Vault.save(new_enc)

@cli.command('delete')
@click.option('--id', prompt=False, required=True)
def delete(id):
    enc_data = Vault.load()
    dec = Vault.decrypt(key, enc_data.decode('utf-8'))
    tmp = Vault.unmarshal(dec)
    new = Vault(
            tmp.username_list,
            tmp.password_list,
            tmp.website_list
        )
    print(tmp)
    id = int(id)
    Vault.delete(
        new,
        id
    )
    new_enc = new.encrypt(key)
    Vault.save(new_enc)

@cli.command('list')
def list():
    enc_data = Vault.load()
    dec = Vault.decrypt(key, enc_data.decode('utf-8'))
    newVault = Vault.unmarshal(dec)
    print('| id  | username')
    print('+-----+------------')
    for i, username in enumerate(newVault.username_list):
        print(f'| {i}   | {username}')
    
@cli.command('show')
@click.option('--id', prompt=False, required=True)
def show(id):
    enc_data = Vault.load()
    dec = Vault.decrypt(key, enc_data.decode('utf-8'))
    newVault = Vault.unmarshal(dec)

    id = int(id)
    username = newVault.username_list[id]
    password = newVault.password_list[id]
    website = newVault.website_list[id]
    print(f'username : {username}\n'
          f'password : {password}\n'
          f'website  : {website}')



if __name__ == '__main__':
 
    key = prompt_master_password()
    cli()
