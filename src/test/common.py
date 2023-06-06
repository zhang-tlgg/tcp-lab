import subprocess
import time
import sys
import os
import atexit


def kill():
    # kill processes
    subprocess.run("killall lwip-server", shell=True, capture_output=True)
    subprocess.run("killall lwip-client", shell=True, capture_output=True)
    subprocess.run("killall lab-server", shell=True, capture_output=True)
    subprocess.run("killall lab-client", shell=True, capture_output=True)


def kill_callback(proc):
    print('Terminating process')
    proc.terminate()
    proc.kill()


def spawn(prefix, target):
    stdout = os.path.join(os.getcwd(), f'{prefix}_{target}-stdout.log')
    stderr = os.path.join(os.getcwd(), f'{prefix}_{target}-stderr.log')
    print(
        f'Spawning {target}, stdout redirected to {stdout}, stderr redirected to {stderr}')
    p = subprocess.Popen(["ninja", f"run-{target}"], stdout=open(
        stdout, 'w'), stderr=open(stderr, 'w'))
    atexit.register(kill_callback, p)
    time.sleep(1)


def spawn_lwip_server(prefix):
    spawn(prefix, 'lwip-server')


def spawn_lwip_client(prefix):
    spawn(prefix, 'lwip-client')


def spawn_lab_server(prefix):
    spawn(prefix, 'lab-server')


def spawn_lab_client(prefix):
    spawn(prefix, 'lab-client')


def spawn_lab_client_tun(prefix):
    spawn(prefix, 'lab-client-tun')


def quit(code):
    kill()
    sys.exit(code)
