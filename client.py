from socket import *
from threading import Thread

def clientHandler():
    conn, addr = s.accept()
    print addr, "is connected"
    while 1:
        data = conn.recv(1024)
        if not data:
            break
        print "Received Message", repr(data)


HOST = "" #localhost
PORT = 15000


s = socket(AF_INET, SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(4)

print "Server is runnig"
#Thread(target=clientHandler).start()
#Thread(target=clientHandler).start()
#Thread(target=clientHandler).start()

for i in range(4):
    Thread(target=clientHandler).start()
s.close()