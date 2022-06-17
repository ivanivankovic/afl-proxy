import socket
import os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while 1:
    data = conn.recv(1024)
    command_string = data.decode("utf-8", "ignore").strip()
    res = os.system("./test1 "+ command_string)
    conn.send(str(res).encode())
conn.close()
