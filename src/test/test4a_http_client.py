import time
import os
from common import kill, spawn_lab_client, spawn_lwip_server, quit

# spawn lwip-server and lab-client
# check http request & response

prefix = 'http_client'

kill()

if not os.path.exists('build.ninja'):
    print('Please run in builddir directory!')
    quit(1)

spawn_lwip_server(prefix)
spawn_lab_client(prefix)

timeout = 10
client_stdout = f'{prefix}_lab-client-stdout.log'
server_stdout = f'{prefix}_lwip-server-stdout.log'
for i in range(timeout):
    print('Reading output:')
    recv_lwip = False
    with open(client_stdout, 'r') as f:
        for line in f:
            line = line.strip()
            if 'lwIP' in line:
                recv_lwip = True
                print('lab-client:', line)

    server_http = False
    with open(server_stdout, 'r') as f:
        for line in f:
            line = line.strip()
            if 'Received "GET" request for URI: "/index.html"' in line:
                server_http = True
                print('lwip-server:', line)

    # check
    if recv_lwip and server_http:
        print('Passed')
        quit(0)
    time.sleep(1)

print('Timeout')
quit(1)
