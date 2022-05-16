import socket
import os
import struct
import OpenSSL
import random
import nacl.secret
import nacl.utils
from OpenSSL import crypto
import time


def receive_file_size(sck: socket.socket):
    fmt = "<Q"
    expected_bytes = struct.calcsize(fmt)
    received_bytes = 0
    stream = bytes()
    while received_bytes < expected_bytes:
        chunk = sck.recv(expected_bytes - received_bytes)
        stream += chunk
        received_bytes += len(chunk)
    filesize = struct.unpack(fmt, stream)[0]
    return filesize


def receive_file(sck: socket.socket, filename):
    filesize = receive_file_size(sck)
    with open(filename, "wb") as f:
        received_bytes = 0
        while received_bytes < filesize:
            chunk = sck.recv(1024)
            if chunk:
                f.write(chunk)
                received_bytes += len(chunk)

print("Listening for instructions...\n")

if __name__ == "__main__":
    ip = "127.0.0.1"
    port = 8000

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ip, port))
    server.listen(5)

    while True:
        client, address = server.accept()
        com_to_client = client.recv(1024)
        com_to_client = com_to_client.decode("utf-8")
        com_to_client = int(com_to_client)
        if com_to_client == 1:
            verificado = 'Generating keys...'
            client.send(bytes(verificado, "utf-8"))
            print('Generating keys for client...')
            st_cert = open("./CA_Files/ca.crt", 'rt').read()
            c = OpenSSL.crypto
            ca_cert = c.load_certificate(c.FILETYPE_PEM, st_cert)
            st_key = open("./CA_Files/ca.key", 'rt').read()
            ca_key = c.load_privatekey(c.FILETYPE_PEM, st_key)
            ca_subj = ca_cert.get_subject()
            client_key = crypto.PKey()
            client_key.generate_key(crypto.TYPE_RSA, 2048)
            client_cert = crypto.X509()
            client_cert.set_version(2)
            client_cert.set_serial_number(random.randint(50000000, 100000000))
            client_subj = client_cert.get_subject()
            client_subj.commonName = "Cliente"
            client_cert.add_extensions([
                crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
                crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=client_cert),
            ])
            client_cert.add_extensions([
                crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_cert),
                crypto.X509Extension(b"extendedKeyUsage", False, b"clientAuth"),
                crypto.X509Extension(b"keyUsage", False, b"digitalSignature"),
            ])
            client_cert.set_issuer(ca_subj)
            client_cert.set_pubkey(client_key)
            client_cert.gmtime_adj_notBefore(0)
            client_cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
            client_cert.sign(ca_key, 'sha256')
            with open("./Client_Files/Client_Key_Cert/client_cert.crt", "wt") as f:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, client_cert).decode("utf-8"))
            with open("./Client_Files/Client_Key_Cert/client_key.key", "wt") as f:
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, client_key).decode("utf-8"))
            print('Key and certificate generated!!')
            print('Closing connection...\n')
            time.sleep(1)
        elif com_to_client == 2:
            print('Encrypting file for client...')
            print("Waiting for file...")
            receive_file(client, "./Client_Files/Encrypted_Files/file_encrypted.txt")
            print("File received")
            print("Generating key...")
            key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
            with open('./Client_Files/Encryption_Keys/filekey_txt.key', 'wb') as filekey:
                filekey.write(key)
            with open('./Client_Files/Encryption_Keys/filekey_txt.key', 'rb') as filekey:
                key = filekey.read()
            box = nacl.secret.SecretBox(key)
            print("Key generated")
            print("Reading file...")
            with open('./Client_Files/Encrypted_Files/file_encrypted.txt', 'rb') as file:
                original = file.read()
            print("Encrypting file...")
            encryptedfile = box.encrypt(original)
            with open('./Client_Files/Encrypted_Files/file_encrypted.txt', 'wb') as encrypted_file:
                encrypted_file.write(encryptedfile)
            print("File encrypted!!")
            print('Closing connection...\n')
            time.sleep(1)
        elif com_to_client == 12:
            print('Encrypting file for client...')
            print("Waiting for file...")
            receive_file(client, "./Client_Files/Encrypted_Files/file_encrypted.docx")
            print("File received")
            print("Generating key...")
            key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
            with open('./Client_Files/Encryption_Keys/filekey_docx.key', 'wb') as filekey:
                filekey.write(key)
            with open('./Client_Files/Encryption_Keys/filekey_docx.key', 'rb') as filekey:
                key = filekey.read()
            box = nacl.secret.SecretBox(key)
            print("Key generated")
            print("Reading file...")
            with open('./Client_Files/Encrypted_Files/file_encrypted.docx', 'rb') as file:
                original = file.read()
            print("Encrypting file...")
            encryptedfile = box.encrypt(original)
            with open('./Client_Files/Encrypted_Files/file_encrypted.docx', 'wb') as encrypted_file:
                encrypted_file.write(encryptedfile)
            print("File encrypted!!")
            print('Closing connection...\n')
            time.sleep(1)
        elif com_to_client == 22:
            print('Encrypting file for client...')
            print("Waiting for file...")
            receive_file(client, "./Client_Files/Encrypted_Files/file_encrypted.xlsx")
            print("File received")
            print("Generating key...")
            key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
            with open('./Client_Files/Encryption_Keys/filekey_xlsx.key', 'wb') as filekey:
                filekey.write(key)
            with open('./Client_Files/Encryption_Keys/filekey_xlsx.key', 'rb') as filekey:
                key = filekey.read()
            box = nacl.secret.SecretBox(key)
            print("Key generated")
            print("Reading file...")
            with open('./Client_Files/Encrypted_Files/file_encrypted.xlsx', 'rb') as file:
                original = file.read()
            print("Encrypting file...")
            encryptedfile = box.encrypt(original)
            with open('./Client_Files/Encrypted_Files/file_encrypted.xlsx', 'wb') as encrypted_file:
                encrypted_file.write(encryptedfile)
            print("File encrypted!!")
            print('Closing connection...\n')
            time.sleep(1)
        elif com_to_client == 3:
            print('Decrypting file for client...')
            print("Waiting for file...")
            receive_file(client, "./Client_Files/Decrypted_Files/file_decrypt.txt")
            print("File received")
            with open('./Client_Files/Encryption_Keys/filekey_txt.key', 'rb') as filekey:
                key = filekey.read()
            box = nacl.secret.SecretBox(key)
            print("Reading file...")
            with open('./Client_Files/Decrypted_Files/file_decrypt.txt', 'rb') as file:
                encrypted = file.read()
            print("Decrypting file...")
            decryptedfile = box.decrypt(encrypted)
            with open('./Client_Files/Decrypted_Files/file_decrypt.txt', 'wb') as decrypted_file:
                decrypted_file.write(decryptedfile)
            print("File decrypted!!")
            print('Closing connection...\n')
            time.sleep(1)
        elif com_to_client == 13:
            print('Decrypting file for client...')
            print("Waiting for file...")
            receive_file(client, "./Client_Files/Decrypted_Files/file_decrypt.docx")
            print("File received")
            with open('./Client_Files/Encryption_Keys/filekey_docx.key', 'rb') as filekey:
                key = filekey.read()
            box = nacl.secret.SecretBox(key)
            print("Reading file...")
            with open('./Client_Files/Decrypted_Files/file_decrypt.docx', 'rb') as file:
                encrypted = file.read()
            print("Decrypting file...")
            decryptedfile = box.decrypt(encrypted)
            with open('./Client_Files/Decrypted_Files/file_decrypt.docx', 'wb') as decrypted_file:
                decrypted_file.write(decryptedfile)
            print("File decrypted!!")
            print('Closing connection...\n')
            time.sleep(1)
        elif com_to_client == 23:
            print('Decrypting file for client...')
            print("Waiting for file...")
            receive_file(client, "./Client_Files/Decrypted_Files/file_decrypt.xlsx")
            print("File received")
            with open('./Client_Files/Encryption_Keys/filekey_xlsx.key', 'rb') as filekey:
                key = filekey.read()
            box = nacl.secret.SecretBox(key)
            print("Reading file...")
            with open('./Client_Files/Decrypted_Files/file_decrypt.xlsx', 'rb') as file:
                encrypted = file.read()
            print("Decrypting file...")
            decryptedfile = box.decrypt(encrypted)
            with open('./Client_Files/Decrypted_Files/file_decrypt.xlsx', 'wb') as decrypted_file:
                decrypted_file.write(decryptedfile)
            print("File decrypted!!")
            print('Closing connection...\n')
            time.sleep(1)
        elif com_to_client == 4:
            print('Signing file for client...')
            print("Waiting for file...")
            receive_file(client, "./Client_Files/Signed_Files/file_signed.txt")
            print("File received")
            with open('./Client_Files/Signed_Files/file_signed.txt', 'rb') as file:
                content_to_sign = file.read()
            print("Signing file...")
            c = OpenSSL.crypto
            st_key = open("./Client_Files/Client_Key_Cert/client_key.key", 'rt').read()
            client_key = c.load_privatekey(c.FILETYPE_PEM, st_key)
            st_cert = open("./Client_Files/Client_Key_Cert/client_cert.crt", 'rt').read()
            client_cert = c.load_certificate(c.FILETYPE_PEM, st_cert)
            sign = crypto.sign(client_key, content_to_sign, 'sha256')
            with open('./Client_Files/Signed_Files/file_signed.txt', 'w') as encrypted_file:
                encrypted_file.write(str(sign))
            print("File signed!!")
            time.sleep(2)
            print("Verifying signature...")
            try:
                verify = crypto.verify(client_cert, sign, content_to_sign, 'sha256')
                print("Error = " + str(verify))
                print('Singature verified!!')
                time.sleep(1)
            except:
                print("Error - Check your file and try again")
                time.sleep(1)
            print('Closing connection...\n')
            time.sleep(2)
        elif com_to_client == 14:
            print('Signing file for client...')
            print("Waiting for file...")
            receive_file(client, "./Client_Files/Signed_Files/file_signed.docx")
            print("File received")
            with open('./Client_Files/Signed_Files/file_signed.docx', 'rb') as file:
                content_to_sign = file.read()
            print("Signing file...")
            c = OpenSSL.crypto
            st_key = open("./Client_Files/Client_Key_Cert/client_key.key", 'rt').read()
            client_key = c.load_privatekey(c.FILETYPE_PEM, st_key)
            content_to_sign = content_to_sign
            sign = crypto.sign(client_key, content_to_sign, 'sha256')
            with open('./Client_Files/Signed_Files/file_signed.docx', 'w') as encrypted_file:
                encrypted_file.write(str(sign))
            print("File signed!!")
            time.sleep(2)
            print("Verifying signature...")
            try:
                verify = crypto.verify(client_cert, sign, content_to_sign, 'sha256')
                print("Error = " + str(verify))
                print('Singature verified!!')
                time.sleep(1)
            except:
                print("Error - Check your file and try again")
                time.sleep(1)
            print('Closing connection...\n')
            time.sleep(2)
        elif com_to_client == 24:
            print('Signing file for client...')
            print("Waiting for file...")
            receive_file(client, "./Client_Files/Signed_Files/file_signed.xlsx")
            print("File received")
            with open('./Client_Files/Signed_Files/file_signed.xlsx', 'rb') as file:
                content_to_sign = file.read()
            print("Signing file...")
            c = OpenSSL.crypto
            st_key = open("./Client_Files/Client_Key_Cert/client_key.key", 'rt').read()
            client_key = c.load_privatekey(c.FILETYPE_PEM, st_key)
            content_to_sign = content_to_sign
            sign = crypto.sign(client_key, content_to_sign, 'sha256')
            with open('./Client_Files/Signed_Files/file_signed.xlsx', 'w') as encrypted_file:
                encrypted_file.write(str(sign))
            print("File signed!!")
            time.sleep(2)
            print("Verifying signature...")
            try:
                verify = crypto.verify(client_cert, sign, content_to_sign, 'sha256')
                print("Error = " + str(verify))
                print('Singature verified!!')
                time.sleep(1)
            except:
                print("Error - Check your file and try again")
                time.sleep(1)
            print('Closing connection...\n')
            time.sleep(2)
        client.close()