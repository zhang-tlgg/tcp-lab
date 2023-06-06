import time
import os
from common import kill, spawn_lab_server, spawn_lwip_client, quit

# spawn lab-server and lwip-client
# check the tcp state machine

prefix = 'termination_server'

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
    client_closed = False
    with open(client_stdout, 'r') as f:
        for line in f:
            line = line.strip()
            if 'tcp_receive: received FIN.' in line:
                client_closed = True
                print('lwip-client:', line)

    transitions = []
    with open(server_stdout, 'r') as f:
        for line in f:
            line = line.strip()
            if 'TCP state transitioned from' in line:
                parts = line.split(' ')
                old_state = parts[4]
                new_state = parts[6]
                transitions.append((old_state, new_state))
                print('lab-server:', line)

    # check state machine
    if len(transitions) >= 5 and client_closed:
        assert(transitions[0] == ('CLOSED', 'LISTEN'))
        assert(transitions[1] == ('CLOSED', 'SYN_RCVD'))
        assert(transitions[2] == ('SYN_RCVD', 'ESTABLISHED'))
        assert(transitions[3] == ('ESTABLISHED', 'FIN_WAIT_1'))
        assert(transitions[4] == ('FIN_WAIT_1', 'FIN_WAIT_2'))
        print('Passed')
        quit(0)
    time.sleep(1)

print('Timeout')
quit(1)
