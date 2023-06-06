import time
import os
from common import kill, spawn_lwip_client, spawn_lab_server, quit

# spawn lab-server and lwip-client
# check http request & response

prefix = 'http_server'

kill()

if not os.path.exists('build.ninja'):
    print('Please run in builddir directory!')
    quit(1)

spawn_lab_server(prefix)
spawn_lwip_client(prefix)

timeout = 10
client_stdout = f'{prefix}_lwip-client-stdout.log'
server_stdout = f'{prefix}_lab-server-stdout.log'
for i in range(timeout):
    print('Reading output:')
    recv_200 = False
    with open(client_stdout, 'r') as f:
        for line in f:
            line = line.strip()
            if 'HTTP/1.1 200 OK' in line:
                recv_200 = True
                print('lwip-client:', line)

    server_http = False
    with open(server_stdout, 'r') as f:
        for line in f:
            line = line.strip()
            if 'GET /index.html' in line:
                server_http = True
                print('lab-server:', line)

    # check
    if recv_200 and server_http:
        print('Passed')
        quit(0)
    time.sleep(1)

print('Timeout')
quit(1)
