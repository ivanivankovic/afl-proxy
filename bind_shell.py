import socket
import os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('0.0.0.0', 1081))
s.listen(10)
conn, addr = s.accept()
print("Connection accepted.\n")
while 1:
    data = conn.recv(1024)
    print("Data: " + str(data))
    command_string = data.decode("utf-8", "ignore").strip()
    command_string = command_string.replace("\'", "")
    if (command_string == ""):
        conn.send((str(0).encode()))
    print("in: " + str(command_string))
    print("command:"+ " ./test1 \'"+ str(command_string) + str("\'  >/dev/null 2>&1"))
    res = os.system("./test1 \'"+ str(command_string) + str("\'  >/dev/null 2>&1"))
    print("out: " + str(res))
    conn.send(str(res).encode())
conn.close()
