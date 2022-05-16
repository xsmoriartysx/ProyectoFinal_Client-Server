import os
import socket
import struct
from os import system
import time
import getpass
import datetime
import json
import shutil

def write_list(a_list):
    with open('./utils/userList.json', "w") as fp:
        json.dump(a_list, fp)

def read_list():
    with open("./utils/userList.json", 'rb') as fp:
        n_list = json.load(fp)
        return n_list

def update_logs(log):
    f = open('./utils/logs.txt', 'w')
    f.write(str(log))
    f.close()

def read_logs():
    f = open('./utils/logs.txt', 'r')
    logs = f.read()
    logs = int(logs)
    f.close()
    return  logs

def write_list_admin(a_list):
    with open('./utils/userAdminList.json', "w") as fp:
        json.dump(a_list, fp)

def read_list_admin():
    with open('./utils/userAdminList.json', 'rb') as fp:
        n_list = json.load(fp)
        return n_list

def write_list_logs(a_list):
    with open('./utils/logsAdminList.json', "w") as fp:
        json.dump(a_list, fp)

def read_list_logs():
    with open('./utils/logsAdminList.json', 'rb') as fp:
        n_list = json.load(fp)
        return n_list

def register_logs(log, user, hour, option):
    listlogs = read_list_logs()
    datetime = str(hour)
    log =  str(log)
    if option== 1:
        newAdminLog = {'log': log, 'user': user, 'hour': datetime, 'register': 'GENERAR/RECUPERAR CLAVES'}
        listlogs.append(newAdminLog)
        write_list_logs(listlogs)
    if option == 2:
        newAdminLog = {'log': log, 'user': user, 'hour': datetime, 'register': 'CIFRAR ARCHIVO'}
        listlogs.append(newAdminLog)
        write_list_logs(listlogs)
    if option == 3:
        newAdminLog = {'log': log, 'user': user, 'hour': datetime, 'register': 'DESCIFRAR ARCHIVO'}
        listlogs.append(newAdminLog)
        write_list_logs(listlogs)
    if option == 4:
        newAdminLog = {'log': log, 'user': user, 'hour': datetime, 'register': 'FIRMAR ARCHIVO'}
        listlogs.append(newAdminLog)
        write_list_logs(listlogs)
    if option == 5:
        newAdminLog = {'log': log, 'user': user, 'hour': datetime, 'register': 'VERIFICAR ARCHIVO FIRMADO'}
        listlogs.append(newAdminLog)
        write_list_logs(listlogs)
    if option == 6:
        newAdminLog = {'log': log, 'user': user, 'hour': datetime, 'register': 'LOGOUT'}
        listlogs.append(newAdminLog)
        write_list_logs(listlogs)
    if option == 7:
        newAdminLog = {'log': log, 'user': user, 'hour': datetime, 'register': 'BITACORA DE ACCESOS'}
        listlogs.append(newAdminLog)
        write_list_logs(listlogs)
salir = False
opcion = 0


def pedirNumeroEntero():
    correcto = False
    num = 0
    while (not correcto):
        try:
            num = int(input("           Elige una opcion: "))
            correcto = True
        except ValueError:
            print('Error, introduce un numero entero')
    return num

def send_file(sck: socket.socket, filename):
    filesize = os.path.getsize(filename)
    sck.sendall(struct.pack("<Q", filesize))
    with open(filename, "rb") as f:
        while read_bytes := f.read(1024):
            sck.sendall(read_bytes)

while not salir:
    salir_login = False
    salir_loginA = False
    salir_bitacora = False
    contlogs = read_logs()

    system("cls")
    print("--------------------------------------------")
    print("||       _____      ____      ____        ||")
    print("||      / ___/     / __ \    / __ \       ||")
    print("||      \__ \     / /_/ /   / / / /       ||")
    print("||     ___/ /    / ____/   / /_/ /        ||")
    print("||    /____/ (_)/_/    (_)/_____/(_)      ||")
    print("||  Software de Protección de Documentos  ||")
    print("||                                        ||")
    print("||               1. LOGIN                 ||")
    print("||              2. REGISTER               ||")
    print("||               3. SALIR                 ||")
    print("--------------------------------------------")
    main_menu_op = pedirNumeroEntero()
    print("--------------------------------------------")

    if main_menu_op == 1:
        login = False
        loginA = False
        system("cls")
        print("--------------------------------------------")
        print("||       _____      ____      ____        ||")
        print("||      / ___/     / __ \    / __ \       ||")
        print("||      \__ \     / /_/ /   / / / /       ||")
        print("||     ___/ /    / ____/   / /_/ /        ||")
        print("||    /____/ (_)/_/    (_)/_____/(_)      ||")
        print("||  Software de Protección de Documentos  ||")
        print("--------------------------------------------")
        su = input("    USER: ")
        sp = getpass.getpass("    PASSWORD: ")
        print("--------------------------------------------")
        time.sleep(1)
        user_list = read_list()
        for i in user_list:
            usuario = []
            for v in i.values():
                usuario.append(v)
            if usuario[0] == su and usuario[1] == sp:
                login = True
                break
            else:
                login = False
        if login:
            contlogs += 1
            update_logs(contlogs)
            system("cls")
            while not salir_login:
                system("cls")
                print("--------------------------------------------")
                print("||       _____      ____      ____        ||")
                print("||      / ___/     / __ \    / __ \       ||")
                print("||      \__ \     / /_/ /   / / / /       ||")
                print("||     ___/ /    / ____/   / /_/ /        ||")
                print("||    /____/ (_)/_/    (_)/_____/(_)      ||")
                print("||  Software de Protección de Documentos  ||")
                print("||                                        ||")
                print("||      1. GENERAR/RECUPERAR CLAVES       ||")
                print("||           2. CIFRAR ARCHIVO            ||")
                print("||         3. DESCIFRAR ARCHIVO           ||")
                print("||   4. FIRMAR ARCHIVO/VERIFICAR FIRMA    ||")
                print("||              5. LOGOUT                 ||")
                print("--------------------------------------------")
                print("--------------------------------------------")
                login_op = pedirNumeroEntero()
                print("--------------------------------------------")
                time.sleep(2)
                if login_op == 1:
                    system("cls")
                    print("GENERAR/RECUPERAR CLAVES")
                    hour = datetime.datetime.now()
                    register_logs(contlogs, su, hour, login_op)
                    print('Starting connection to server...')
                    if __name__ == "__main__":
                        ip = "127.0.0.1"
                        port = 8000
                        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        server.connect((ip, port))
                        print('Connected to server...')
                        com_to_server = str(login_op)
                        print('Requesting service: GENERAR/RECUPERAR CLAVES')
                        server.send(bytes(com_to_server, "utf-8"))
                        buffer = server.recv(1024)
                        buffer = buffer.decode("utf-8")
                        print(f"Server connection - {buffer}")
                    time.sleep(2)
                elif login_op == 2:
                    system("cls")
                    print("CIFRAR ARCHIVO")
                    hour = datetime.datetime.now()
                    register_logs(contlogs, su, hour, login_op)
                    print('Select the file you want to encrypt: ')
                    content_dir = os.listdir('../Client/Files/Files_To_Encrypt')
                    for i in content_dir:
                        print('-', i)
                    file_name = input('Type the file to encrypt(.txt/.docx/.xlsx): ')
                    route_file = './Files/Files_To_Encrypt/' + file_name
                    print('Starting connection to server...')
                    if 'txt' in file_name:
                        print('txt')
                        if __name__ == "__main__":
                            ip = "127.0.0.1"
                            port = 8000
                            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            server.connect((ip, port))
                            print('Connected to server...')
                            com_to_server = str(login_op)
                            print('Requesting service: CIFRAR ARCHIVO')
                            server.send(bytes(com_to_server, "utf-8"))
                            print("Server connection - Encrypting file..")
                            print("Sending file...")
                            send_file(server, route_file)
                            print("File sent")
                    elif 'docx' in file_name:
                        print('docx')
                        if __name__ == "__main__":
                            ip = "127.0.0.1"
                            port = 8000
                            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            server.connect((ip, port))
                            print('Connected to server...')
                            com_to_server = str(login_op+10)
                            print('Requesting service: CIFRAR ARCHIVO')
                            server.send(bytes(com_to_server, "utf-8"))
                            print("Server connection - Encrypting file..")
                            print("Sending file...")
                            send_file(server, route_file)
                            print("File sent")
                    elif 'xlsx' in file_name:
                        print('xlsx')
                        if __name__ == "__main__":
                            ip = "127.0.0.1"
                            port = 8000
                            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            server.connect((ip, port))
                            print('Connected to server...')
                            com_to_server = str(login_op+20)
                            print('Requesting service: CIFRAR ARCHIVO')
                            server.send(bytes(com_to_server, "utf-8"))
                            print("Server connection - Encrypting file..")
                            print("Sending file...")
                            send_file(server, route_file)
                            print("File sent")
                    else:
                        print('Type correctly the name of your file or upload it to the dir /Client/Files/')
                    time.sleep(2)
                elif login_op == 3:
                    contenidos = os.listdir('../Server/Client_Files/Encrypted_Files')
                    for elemento in contenidos:
                        route_elemento = '../Server/Client_Files/Encrypted_Files/' + elemento
                        shutil.copy(route_elemento, "../Client/Files/Files_To_Decrypt")
                    system("cls")
                    print("DESCIFRAR ARCHIVO")
                    hour = datetime.datetime.now()
                    register_logs(contlogs, su, hour, login_op)
                    print('Select the file you want to decrypt: ')
                    content_dir = os.listdir('../Client/Files/Files_To_Decrypt/')
                    for i in content_dir:
                        print('-', i)
                    file_name = input('Type the file to encrypt(.txt/.docx/.xlsx): ')
                    route_file = './Files/Files_To_Decrypt/' + file_name
                    print('Starting connection to server...')
                    if 'txt' in file_name:
                        print('txt')
                        if __name__ == "__main__":
                            ip = "127.0.0.1"
                            port = 8000
                            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            server.connect((ip, port))
                            print('Connected to server...')
                            com_to_server = str(login_op)
                            print('Requesting service: DESCIFRAR ARCHIVO')
                            server.send(bytes(com_to_server, "utf-8"))
                            print("Server connection - Decrypting file...")
                            print("Sending file...")
                            send_file(server, route_file)
                            print("File sent")
                    elif 'docx' in file_name:
                        print('docx')
                        if __name__ == "__main__":
                            ip = "127.0.0.1"
                            port = 8000
                            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            server.connect((ip, port))
                            print('Connected to server...')
                            com_to_server = str(login_op + 10)
                            print('Requesting service: DESCIFRAR ARCHIVO')
                            server.send(bytes(com_to_server, "utf-8"))
                            print("Server connection - Decrypting file...")
                            print("Sending file...")
                            send_file(server, route_file)
                            print("File sent")
                    elif 'xlsx' in file_name:
                        print('xlsx')
                        if __name__ == "__main__":
                            ip = "127.0.0.1"
                            port = 8000
                            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            server.connect((ip, port))
                            print('Connected to server...')
                            com_to_server = str(login_op + 20)
                            print('Requesting service: DESCIFRAR ARCHIVO')
                            server.send(bytes(com_to_server, "utf-8"))
                            print("Server connection - Decrypting file...")
                            print("Sending file...")
                            send_file(server, route_file)
                            print("File sent")
                    else:
                        print('Type correctly the name of your file or upload it to the dir /Client/Files/')
                    time.sleep(2)
                elif login_op == 4:
                    contenidos = os.listdir('../Client/Files/Files_To_Encrypt')
                    for elemento in contenidos:
                        route_elemento = '../Client/Files/Files_To_Encrypt/' + elemento
                        shutil.copy(route_elemento, "../Client/Files/Files_To_Sign")

                    contenidos = os.listdir('../Client/Files/Files_To_Decrypt')
                    for elemento in contenidos:
                        route_elemento = '../Client/Files/Files_To_Decrypt/' + elemento
                        shutil.copy(route_elemento, "../Client/Files/Files_To_Sign")
                    system("cls")
                    print("FIRMAR ARCHIVO")
                    hour = datetime.datetime.now()
                    register_logs(contlogs, su, hour, login_op)
                    print('Select the file you want to sign: ')
                    content_dir = os.listdir('../Client/Files/Files_To_Sign/')
                    for i in content_dir:
                        print('-', i)
                    file_name = input('Type the file to encrypt(.txt/.docx/.xlsx): ')
                    route_file = './Files/Files_To_Sign/' + file_name
                    print('Starting connection to server...')
                    if 'txt' in file_name:
                        print('txt')
                        if __name__ == "__main__":
                            ip = "127.0.0.1"
                            port = 8000
                            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            server.connect((ip, port))
                            print('Connected to server...')
                            com_to_server = str(login_op)
                            print('Requesting service: FIRMAR ARCHIVO')
                            server.send(bytes(com_to_server, "utf-8"))
                            print("Server connection - Signing file...")
                            print("Sending file...")
                            send_file(server, route_file)
                            print("File sent")
                    elif 'docx' in file_name:
                        print('docx')
                        if __name__ == "__main__":
                            ip = "127.0.0.1"
                            port = 8000
                            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            server.connect((ip, port))
                            print('Connected to server...')
                            com_to_server = str(login_op + 10)
                            print('Requesting service: FIRMAR ARCHIVO')
                            server.send(bytes(com_to_server, "utf-8"))
                            print("Server connection - Signing file...")
                            print("Sending file...")
                            send_file(server, route_file)
                            print("File sent")
                    elif 'xlsx' in file_name:
                        print('xlsx')
                        if __name__ == "__main__":
                            ip = "127.0.0.1"
                            port = 8000
                            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            server.connect((ip, port))
                            print('Connected to server...')
                            com_to_server = str(login_op + 20)
                            print('Requesting service: FIRMAR ARCHIVO')
                            server.send(bytes(com_to_server, "utf-8"))
                            print("Server connection - Signing file...")
                            print("Sending file...")
                            send_file(server, route_file)
                            print("File sent")
                    else:
                        print('Type correctly the name of your file or upload it to the dir /Client/Files/')
                    time.sleep(2)
                elif login_op == 5:
                    system("cls")
                    salir_login = True
                    print("Logging out...")
                    hour = datetime.datetime.now()
                    register_logs(contlogs, su, hour, login_op)
                    time.sleep(1)
        else:
            listAdmin = read_list_admin()
            for i in listAdmin:
                usuarioA = []
                for v in i.values():
                    usuarioA.append(v)
                if usuarioA[0] == su and usuarioA[1] == sp:
                    loginA = True
                    break
                else:
                    loginA = False
            if loginA:
                contlogs += 1
                update_logs(contlogs)
                system("cls")
                while not salir_loginA:
                    system("cls")
                    print("--------------------------------------------")
                    print("||       _____      ____      ____        ||")
                    print("||      / ___/     / __ \    / __ \       ||")
                    print("||      \__ \     / /_/ /   / / / /       ||")
                    print("||     ___/ /    / ____/   / /_/ /        ||")
                    print("||    /____/ (_)/_/    (_)/_____/(_)      ||")
                    print("||  Software de Protección de Documentos  ||")
                    print("||                                        ||")
                    print("||         1. BITÁCORA DE ACCESOS         ||")
                    print("||               2. SALIR                 ||")
                    print("--------------------------------------------")
                    print("--------------------------------------------")
                    login_op = pedirNumeroEntero()
                    print("--------------------------------------------")
                    time.sleep(2)
                    if login_op == 1:
                        system("cls")
                        print("BITÁCORA DE ACCESOS")
                        hour = datetime.datetime.now()
                        register_logs(contlogs, su, hour, 7)

                        exit = 'NO'
                        while exit != 'YES':
                            system("cls")
                            print("--------------------------------------------")
                            print("||       _____      ____      ____        ||")
                            print("||      / ___/     / __ \    / __ \       ||")
                            print("||      \__ \     / /_/ /   / / / /       ||")
                            print("||     ___/ /    / ____/   / /_/ /        ||")
                            print("||    /____/ (_)/_/    (_)/_____/(_)      ||")
                            print("||  Software de Protección de Documentos  ||")
                            print("||                                        ||")
                            print("||           BITÁCORA DE ACCESOS          ||")
                            print("--------------------------------------------")
                            logs = read_list_logs()
                            for i in logs:
                                loginfo = []
                                for v in i.values():
                                    loginfo.append(v)
                                print('LOG NO: ' + loginfo[0])
                                print('USER: ' + loginfo[1])
                                print('DATETIME: ' + loginfo[2])
                                print('REGISTER: ' + loginfo[3])
                                print("--------------------------------------------")
                            print("--------------------------------------------")
                            exit = input("          EXIT(YES/NO): ")
                            time.sleep(2)
                    elif login_op == 2:
                        system("cls")
                        salir_loginA = True
                        print("SALIR SUPERUSER")
                        hour = datetime.datetime.now()
                        register_logs(contlogs, su, hour, 6)
                        time.sleep(2)

        if login == False and loginA == False:
            print('||     User not registered - Try Again    ||')
            print("--------------------------------------------")
            time.sleep(2)

    elif main_menu_op == 2:
        sp = "a"
        vp = "b"
        while sp != vp:
            system("cls")
            print("Opcion 2")
            print("--------------------------------------------")
            print("||       _____      ____      ____        ||")
            print("||      / ___/     / __ \    / __ \       ||")
            print("||      \__ \     / /_/ /   / / / /       ||")
            print("||     ___/ /    / ____/   / /_/ /        ||")
            print("||    /____/ (_)/_/    (_)/_____/(_)      ||")
            print("||  Software de Protección de Documentos  ||")
            print("||                                        ||")
            print("||           REGISTRO DE USUARIO          ||")
            print("--------------------------------------------")
            su = input("    INGRESA USUARIO: ")
            sp = getpass.getpass("    INGRESA CONTRASENA: ")
            vp = getpass.getpass("    CONFIRMA CONTRASENA: ")
            print("--------------------------------------------")
            if sp != vp:
                print('               WRONG PASSWORD               ')
                print("--------------------------------------------")
                try_again = input('          TRY AGAIN (YES/NO): ')
                print("--------------------------------------------")
                if try_again == "YES":
                    time.sleep(1)
                    continue
                else:
                    break
            else:
                user_list = read_list()
                new_user = {'user': su, 'password': sp}
                user_list.append(new_user)
                write_list(user_list)
                print('                USER REGISTERED             ')
                print("--------------------------------------------")
            time.sleep(1)
        time.sleep(1)
    elif main_menu_op == 3:
        salir = True
    else:
        print("Introduce un numero entre 1 y 3")
print("||             SEE YOU LATER!!            ||")
print("--------------------------------------------")



