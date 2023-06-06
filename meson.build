project('tcplab', 'c', 'cpp',
  version : '0.1',
  default_options : ['warning_level=3', 'cpp_std=c++14', 'b_sanitize=address'])

lwip_path = 'thirdparty/lwip-2.1.2/src'
lwip_sources = [
  lwip_path / 'core/init.c',
  lwip_path / 'core/def.c',
  lwip_path / 'core/dns.c',
  lwip_path / 'core/inet_chksum.c',
  lwip_path / 'core/ip.c',
  lwip_path / 'core/mem.c',
  lwip_path / 'core/memp.c',
  lwip_path / 'core/netif.c',
  lwip_path / 'core/pbuf.c',
  lwip_path / 'core/raw.c',
  lwip_path / 'core/stats.c',
  lwip_path / 'core/sys.c',
  lwip_path / 'core/altcp.c',
  lwip_path / 'core/altcp_alloc.c',
  lwip_path / 'core/altcp_tcp.c',
  lwip_path / 'core/tcp.c',
  lwip_path / 'core/tcp_in.c',
  lwip_path / 'core/tcp_out.c',
  lwip_path / 'core/timeouts.c',
  lwip_path / 'core/udp.c',
  lwip_path / 'core/ipv4/autoip.c',
  lwip_path / 'core/ipv4/dhcp.c',
  lwip_path / 'core/ipv4/etharp.c',
  lwip_path / 'core/ipv4/icmp.c',
  lwip_path / 'core/ipv4/igmp.c',
  lwip_path / 'core/ipv4/ip4_frag.c',
  lwip_path / 'core/ipv4/ip4.c',
  lwip_path / 'core/ipv4/ip4_addr.c',
  lwip_path / 'api/api_lib.c',
  lwip_path / 'api/api_msg.c',
  lwip_path / 'api/err.c',
  lwip_path / 'api/if_api.c',
  lwip_path / 'api/netbuf.c',
  lwip_path / 'api/netdb.c',
  lwip_path / 'api/netifapi.c',
  lwip_path / 'api/sockets.c',
  lwip_path / 'api/tcpip.c',
  lwip_path / 'netif/ethernet.c',
  lwip_path / 'apps/http/altcp_proxyconnect.c',
  lwip_path / 'apps/http/fs.c',
  lwip_path / 'apps/http/http_client.c',
  lwip_path / 'apps/http/httpd.c',
]

lwip_incdir = include_directories('include', lwip_path / 'include')

lwip_lib = static_library('lwip',
                          lwip_sources,
                          'src/lwip_common.cpp',
                          'src/common.cpp',
                          c_args : '-fno-common',
                          cpp_args : '-fno-common',
                          include_directories: lwip_incdir)
lab_sources = [
        'src/lab/ip.cpp',
        'src/lab/tcp.cpp',
]

common_sources = [
        'src/lab/timers.cpp',
        'src/common.cpp',
]

lwip_client = executable('lwip-client',
           common_sources,
           'src/lwip/lwip-client.cpp',
           link_with: lwip_lib,
           include_directories: lwip_incdir)

lwip_server = executable('lwip-server',
           common_sources,
           'src/lwip/lwip-server.cpp',
           link_with: lwip_lib,
           include_directories: lwip_incdir)

incdir = include_directories('include')

lab_client = executable('lab-client',
            lab_sources,
            common_sources,
            'src/lab/lab-client.cpp',
            include_directories: incdir)

lab_server = executable('lab-server',
            lab_sources,
            common_sources,
            'src/lab/lab-server.cpp',
            include_directories: incdir)

run_target('run-lwip-server',
  depends: [lwip_server],
  command : [lwip_server, '-l', 's', '-r', 'c', '-p', 'server.pcap']
)

run_target('run-lwip-client',
  depends: [lwip_client],
  command : [lwip_client, '-l', 'c', '-r', 's', '-p', 'client.pcap']
)

run_target('run-lwip-client-tun',
  depends: [lwip_client],
  command : ['sudo', lwip_client, '-t', 'utun', '-p', 'lwip-client.pcap']
)

run_target('run-lab-client',
  depends: [lab_client],
  command : [lab_client, '-l', 'c', '-r', 's', '-p', 'lab-client.pcap']
)

run_target('run-lab-client-tun',
  depends: [lab_client],
  command : [lab_client, '-t', 'utun', '-p', 'lab-client.pcap']
)

run_target('run-lab-server',
  depends: [lab_server],
  command : [lab_server, '-l', 's', '-r', 'c', '-p', 'lab-server.pcap']
)

# testing
test1_seq_compare = executable('test1-seq-compare',
            lab_sources,
            common_sources,
            'src/test/test1_seq_compare.cpp',
            include_directories: incdir)
test('test1 seq comparison', test1_seq_compare)

test2_initial_seq = executable('test2-initial-seq',
            lab_sources,
            common_sources,
            'src/test/test2_initial_seq.cpp',
            include_directories: incdir)
test('test2 initial seq generation', test2_initial_seq)

root = meson.source_root()
python3 = import('python').find_installation('python3')
sudo = find_program('sudo')

test('test3a 3-way handshake (client)',
    python3,
    args: [root / 'src/test/test3a_3way_handshake_client.py'],
    is_parallel : false)

test('test3b 3-way handshake (server)',
    python3,
    args: [root / 'src/test/test3b_3way_handshake_server.py'],
    is_parallel : false)

test('test4a http request & response (client)',
    python3,
    args: [root / 'src/test/test4a_http_client.py'],
    is_parallel : false)

test('test4b http request & response (server)',
    python3,
    args: [root / 'src/test/test4b_http_server.py'],
    is_parallel : false)

test('test5a connection termination (client)',
    python3,
    args: [root / 'src/test/test5a_termination_client.py'],
    is_parallel : false)

test('test5b connection termination (server)',
    python3,
    args: [root / 'src/test/test5b_termination_server.py'],
    is_parallel : false)

test('test6 visit baidu (client) (requires sudo)',
    sudo,
    args: ['python3', root / 'src/test/test6_visit_baidu.py'],
    is_parallel : false)