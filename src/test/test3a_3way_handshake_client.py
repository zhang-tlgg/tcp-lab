import time
import os
from common import kill, spawn_lab_client, spawn_lwip_server, quit

# spawn lwip-server and lab-client
# check the tcp state machine

prefix = '3way_handshake_client'

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
    transitions = []
    with open(client_stdout, 'r') as f:
        for line in f:
            line = line.strip()
            if 'TCP state transitioned from' in line:
                parts = line.split(' ')
                old_state = parts[4]
                new_state = parts[6]
                transitions.append((old_state, new_state))
                print('lab-client:', line)

    server_established = False
    with open(server_stdout, 'r') as f:
        for line in f:
            line = line.strip()
            if 'TCP connection established' in line:
                server_established = True
                print('lwip-server:', line)

    # check state machine
    if len(transitions) >= 2 and server_established:
        assert(transitions[0] == ('CLOSED', 'SYN_SENT'))
        assert(transitions[1] == ('SYN_SENT', 'ESTABLISHED'))
        print('Passed')
        quit(0)
    time.sleep(1)

print('Timeout')
quit(1)
