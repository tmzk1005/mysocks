#!/usr/bin/env python3
# coding=utf-8
"""
A simple and incomplete sock5 protocol implementation.
"""
import argparse
import asyncio
import logging
import os
import random
import socket
import struct
import sys
from functools import partial

BUFFER_SIZE = 4096

VER_5 = 0x05
CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP_ASSOCIATE = 0x03

ATYP_IPV4 = 0x01
ATYP_DOMAINNAME = 0x03
ATYP_IPV6 = 0x04

METHOD_NO_AUTH = 0x00

_config = {
    "mode": "local",
    "host": "0.0.0.0",
    "port": 1080,
    "socks5_host": '127.0.0.1',
    "socks5_port": 51080,
    "secret": "whaterver some string",
    "log": "darksocks.log"
}


def _shuffle(secret):
    keys = list(range(256))
    random.seed(secret)
    random.shuffle(keys)
    values = list(range(256))
    random.shuffle(values)
    encode_map = {}
    decode_map = {}
    for k in range(256):
        encode_map[keys[k]] = values[k]
        decode_map[values[k]] = keys[k]
    return encode_map, decode_map


def _do_map(data, map_table):
    arr = bytearray(len(data))
    for index in range(len(data)):
        arr[index] = map_table[data[index]]
    return bytes(arr)


encode = None
decode = None


def init_cipher():
    encode_map, decode_map = _shuffle(_config['secret'])
    global encode, decode
    encode = partial(_do_map, map_table=encode_map)
    decode = partial(_do_map, map_table=decode_map)


async def resolve_scoks5(reader, writer):
    data = await reader.readexactly(2)
    data = decode(data)
    version = data[0]
    if version != VER_5:
        # only support socks5
        writer.close()
        return None, None
    method_count = data[1]
    data = await reader.readexactly(method_count)
    data = decode(data)
    if METHOD_NO_AUTH not in data:
        # only support no auth method
        writer.close()
        return None, None
    writer.write(encode(b'\x05\x00'))
    await writer.drain()
    data = await reader.readexactly(4)
    data = decode(data)
    cmd = data[1]
    if cmd != CMD_CONNECT:
        # only support cmd=connect
        writer.close()
        return None, None
    atyp = data[3]
    if atyp == ATYP_IPV4:
        data = await reader.readexactly(6)
        data = decode(data)
        ip4_bin = data[:4]
        port_bin = data[4:6]
        ip = socket.inet_ntop(socket.AF_INET, ip4_bin)
        port = struct.unpack('>H', port_bin)[0]
    elif atyp == ATYP_IPV6:
        data = await reader.readexactly(18)
        data = decode(data)
        ip6_bin = data[:16]
        port_bin = data[16:18]
        ip = socket.inet_ntop(socket.AF_INET6, ip6_bin)
        port = struct.unpack('>H', port_bin)[0]
    elif atyp == ATYP_DOMAINNAME:
        data = await reader.readexactly(1)
        data = decode(data)
        domain_bytes_count = data[0]
        data = await reader.readexactly(domain_bytes_count)
        data = decode(data)
        domain = data.decode('utf-8')
        data = await reader.readexactly(2)
        data = decode(data)
        port = struct.unpack('>H', data)[0]
        loop = asyncio.get_running_loop()
        addrinfo_list = await loop.getaddrinfo(
            host=domain, port=port, proto=socket.IPPROTO_TCP)
        addrinfo = random.choice(addrinfo_list)
        ip = addrinfo[-1][0]
    # we have ip and port now, going to connect to remote
    remote_reader, remote_writer = await asyncio.open_connection(ip, port)
    me_sockname = remote_writer.get_extra_info('sockname')
    if len(me_sockname) == 4:
        me_type = ATYP_IPV6
        me_family = socket.AF_INET6
    else:
        me_type = ATYP_IPV4
        me_family = socket.AF_INET
    me_ip = me_sockname[0]
    me_port = me_sockname[1]
    reply_data = b'\x05\x00\x00' + \
        struct.pack(">B", me_type) + \
        socket.inet_pton(me_family, me_ip) + \
        struct.pack(">H", me_port)
    reply_data = encode(reply_data)
    writer.write(reply_data)
    await writer.drain()
    return remote_reader, remote_writer


async def pipe(reader, writer, code):
    while not writer.is_closing():
        try:
            data = await reader.read(BUFFER_SIZE)
        except (ConnectionResetError, BrokenPipeError):
            writer.close()
            return
        if not data:
            writer.close()
            break
        data = code(data)
        writer.write(data)
        try:
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            return


async def tunel(client_reader, client_writer):
    if _config['mode'] == 'local':
        host, port = _config['socks5_host'], _config['socks5_port']
        try:
            remote_reader, remote_writer = await asyncio.open_connection(host, port)
        except ConnectionRefusedError:
            return
    else:
        try:
            remote_reader, remote_writer = await resolve_scoks5(
                client_reader, client_writer)
        except (ConnectionRefusedError,
                ConnectionResetError,
                asyncio.streams.IncompleteReadError,
                BrokenPipeError):
            return

    if not remote_reader or not remote_writer:
        return

    if _config['mode'] == 'local':
        asyncio.create_task(pipe(client_reader, remote_writer, encode))
        asyncio.create_task(pipe(remote_reader, client_writer, decode))
    else:
        asyncio.create_task(pipe(client_reader, remote_writer, decode))
        asyncio.create_task(pipe(remote_reader, client_writer, encode))


async def relay(cccb):
    host, port = _config['host'], _config['port']
    server = await asyncio.start_server(cccb, host, port)
    addr = server.sockets[0].getsockname()
    logging.info(f'Serving in {_config["mode"]} mode on {addr}')
    async with server:
        await server.serve_forever()


def main():
    logging.basicConfig(level=logging.INFO)
    init_cipher()
    try:
        asyncio.run(relay(tunel))
    except KeyboardInterrupt:
        logging.info('Got ctrl-c, stopping ...')


def _parse_args():
    parser = argparse.ArgumentParser(description='Help you google~')
    parser.add_argument('-m', '--mode',
                        choices=['local', 'server'],
                        dest='mode',
                        default='local',
                        help='the run mode, local or server (default: local)')
    parser.add_argument('--host',
                        dest='host',
                        default='0.0.0.0',
                        help='the ip listen to (default: 0.0.0.0)')
    parser.add_argument('-p', '--port',
                        dest='port',
                        type=int,
                        default=0,
                        help='the port listen to (default: 1080 for local and 51080 for server)')
    parser.add_argument('-H', '--socks5_host',
                        dest='socks5_host',
                        default='127.0.0.1',
                        help='the socks5 proxy server ip address, this is required while mode is local')
    parser.add_argument('-P', '--socks5_port',
                        dest='socks5_port',
                        type=int,
                        default=51080,
                        help='the socks5 proxy server listening port (default: 51080)')
    parser.add_argument('-d', '--daemon',
                        dest='daemon',
                        action='store_const',
                        const=True,
                        default=False,
                        help='run as daemon (default: False)')
    parser.add_argument('-s', '--secret',
                        dest='secret',
                        required=True,
                        help='the secret key use to run this program, '
                        'a local server can only communicate to a socks5 server run with the same secret key.')
    parser.add_argument('-l', '--log',
                        dest='log',
                        default='darksocks.log',
                        help='where to write log file (default: ./darksocks.log)')
    global _config
    _config = vars(parser.parse_args())
    if _config['port'] == 0:
        _config['port'] = 1080 if _config['mode'] == 'local' else 51080


def _daemon():
    try:
        if os.fork() > 0:
            raise SystemExit(0)
    except OSError:
        raise RuntimeError('fork #1 failed')
    os.chdir('/')
    os.umask(0)
    os.setsid()
    try:
        if os.fork() > 0:
            raise SystemExit(0)
    except OSError:
        raise RuntimeError('fork #2 failed')
    sys.stdout.flush()
    sys.stderr.flush()
    with open('/dev/null', 'rb', 0) as _f:
        os.dup2(_f.fileno(), sys.stdin.fileno())
    with open('/dev/null', 'ab', 0) as _f:
        os.dup2(_f.fileno(), sys.stdout.fileno())
    with open('/dev/null', 'ab', 0) as _f:
        os.dup2(_f.fileno(), sys.stderr.fileno())


if __name__ == "__main__":
    _parse_args()
    if _config['daemon']:
        _daemon()
    main()
