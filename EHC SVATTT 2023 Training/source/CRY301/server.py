import random
import socketserver
import sys


def easyone(x):
    assert(x < 2 ** 128)
    x ^= x >> (64 + 19)
    x *= 0xd3856e824d9c8a26aef65c0fe1cc96db
    x &= 0xffffffffffffffffffffffffffffffff
    x ^= x >> (64 + 3)
    x *= 0xe44035c8f8387dc11dd3dd67097007cb
    x &= 0xffffffffffffffffffffffffffffffff
    x ^= x >> (64 + 20)
    x *= 0xc9f54782b4f17cb68ecf11d7b378e445
    x &= 0xffffffffffffffffffffffffffffffff
    x ^= x >> (64 + 2)
    return x


def alittlebitharderone(x):
    assert(x < 2 ** 128)
    x ^= x >> 19
    x *= 0xd3856e824d9c8a26aef65c0fe1cc96db
    x &= 0xffffffffffffffffffffffffffffffff
    x ^= x >> 3
    x *= 0xe44035c8f8387dc11dd3dd67097007cb
    x &= 0xffffffffffffffffffffffffffffffff
    x ^= x >> 20
    x *= 0xc9f54782b4f17cb68ecf11d7b378e445
    x &= 0xffffffffffffffffffffffffffffffff
    x ^= x >> 2
    return x


def rewards():
    try:
        with open('flag.txt', 'rb') as f:
            flag = f.read()
            return b'Congrats, here is your flag: %s' % (flag)
    except Exception as e:
        print(e)
        return b'Server is not configured correctly. Please contact admins to fix the problem'


class RequestHandler(socketserver.StreamRequestHandler):

    def handle(self):
        try:
            secret_number = random.randint(2**127, 2**128)
            self.request.sendall(b'First round: ',)
            self.request.sendall(str(easyone(secret_number)).encode())
            self.request.sendall(b'\n')

            # Yes, I do allow you to try multiple times. But please
            # remember that this is NOT a bruteforce challenge.
            while True:
                try:
                    self.request.sendall(b'What is the secret number? ')
                    s = int(self.rfile.readline().decode())
                except ValueError:
                    self.request.sendall(
                        b'THIS IS A CRYPTOGRAPHIC CHALLENGE!!!\n')
                    continue

                if s != secret_number:
                    self.request.sendall(b'Oops\n')
                    continue

                break

            secret_number = random.randint(2**127, 2**128)
            self.request.sendall(b'Second round: ',)
            self.request.sendall(
                str(alittlebitharderone(secret_number)).encode())
            self.request.sendall(b'\n')

            while True:
                try:
                    self.request.sendall(b'What is the secret number? ')
                    s = int(self.rfile.readline().decode())
                except ValueError:
                    self.request.sendall(
                        b'THIS IS A CRYPTOGRAPHIC CHALLENGE!!!\n')
                    continue

                if s != secret_number:
                    self.request.sendall(b'Oops\n')
                    continue

                break

            # if you reach here, you deserve a reward!!!
            print("{} solved the challenge".format(self.client_address[0]))
            self.request.sendall(rewards())
            self.request.sendall(b'\n')

        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            print("{} disconnected".format(self.client_address[0]))


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


def main(argv):
    host, port = '0.0.0.0', 8000

    if len(argv) == 2:
        port = int(argv[1])
    elif len(argv) >= 3:
        host, port = argv[1], int(argv[2])

    sys.stderr.write('Listening {}:{}\n'.format(host, port))
    server = ThreadedTCPServer((host, port), RequestHandler)
    server.daemon_threads = True
    server.allow_reuse_address = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()


if __name__ == '__main__':
    main(sys.argv)