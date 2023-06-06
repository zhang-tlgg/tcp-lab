import time
import os
from common import kill, spawn_lab_client, spawn_lwip_server, quit

# spawn lwip-server and lab-client
# check the tcp state machine

prefix = 'termination_client'

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

    server_closed = False
    with open(server_stdout, 'r') as f:
        for line in f:
            line = line.strip()
            if 'TCP connection closed' in line:
                server_closed = True
                print('lwip-server:', line)

    # check state machine
    if len(transitions) >= 5 and server_closed:
        assert(transitions[0] == ('CLOSED', 'SYN_SENT'))
        assert(transitions[1] == ('SYN_SENT', 'ESTABLISHED'))
        assert(transitions[2] == ('ESTABLISHED', 'CLOSE_WAIT'))
        assert(transitions[3] == ('CLOSE_WAIT', 'LAST_ACK'))
        assert(transitions[4] == ('LAST_ACK', 'CLOSED'))
        print('Passed')
        quit(0)
    time.sleep(1)

print('Timeout')
quit(1)
