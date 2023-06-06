import time
import os
import subprocess
import atexit
from common import kill, spawn_lab_client_tun, quit, kill_callback

if os.getuid() != 0:
    print('Please run this test with sudo!')
    quit(1)

prefix = 'visit_baidu'

kill()

if not os.path.exists('build.ninja'):
    print('Please run in builddir directory!')
    quit(1)

socat = subprocess.Popen(
    ["socat", "TCP-LISTEN:80,reuseaddr,fork", "TCP:www.baidu.com:80"])
atexit.register(kill_callback, socat)

spawn_lab_client_tun(prefix)

timeout = 10
client_stdout = f'{prefix}_lab-client-tun-stdout.log'
for i in range(timeout):
    print('Reading output:')
    recv_baidu = False
    with open(client_stdout, 'r') as f:
        for line in f:
            line = line.strip()
            if 'www.baidu.com' in line:
                recv_baidu = True
                print('lab-client:', line)

    # check
    if recv_baidu:
        print('Passed')
        quit(0)
    time.sleep(1)

print('Timeout')
quit(1)
