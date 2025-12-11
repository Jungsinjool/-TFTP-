<details> <summary><strong>📌 Click to expand code</strong></summary>
#!/usr/bin/env python3
import argparse
import os
import socket
import struct
import sys

# 기본 TFTP 설정
TFTP_PORT = 69
TFTP_TIMEOUT = 5.0
TFTP_BLOCK_SIZE = 512

# Opcodes
OP_RRQ = 1
OP_WRQ = 2
OP_DATA = 3
OP_ACK = 4
OP_ERROR = 5


def build_request(opcode: int, filename: str, mode: str = "octet") -> bytes:
    return struct.pack("!H", opcode) + filename.encode() + b'\x00' + mode.encode() + b'\x00'


def build_ack(block_number: int) -> bytes:
    return struct.pack("!HH", OP_ACK, block_number)


def build_data(block_number: int, data: bytes) -> bytes:
    return struct.pack("!HH", OP_DATA, block_number) + data


def parse_error_packet(packet: bytes):
    _, error_code = struct.unpack("!HH", packet[:4])
    msg = packet[4:-1].decode(errors="ignore")
    return error_code, msg


def tftp_get(host: str, port: int, filename: str):
    if os.path.exists(filename):
        print(f"에러: 로컬에 이미 '{filename}' 파일이 존재합니다.")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TFTP_TIMEOUT)

    try:
        req = build_request(OP_RRQ, filename)
        sock.sendto(req, (host, port))

        file = open(filename, "wb")
        expected_block = 1

        while True:
            try:
                data, addr = sock.recvfrom(4 + TFTP_BLOCK_SIZE)
            except socket.timeout:
                print("에러: 서버 응답 timeout")
                file.close()
                os.remove(filename)
                return

            opcode = struct.unpack("!H", data[:2])[0]

            if opcode == OP_ERROR:
                error_code, msg = parse_error_packet(data)
                print(f"서버 ERROR({error_code}): {msg}")
                file.close()
                os.remove(filename)
                return

            if opcode != OP_DATA:
                print(f"에러: 예상치 못한 opcode 수신: {opcode}")
                file.close()
                os.remove(filename)
                return

            block_number = struct.unpack("!H", data[2:4])[0]
            payload = data[4:]

            if block_number == expected_block:
                file.write(payload)
                ack = build_ack(block_number)
                sock.sendto(ack, addr)
                expected_block += 1
            else:
                sock.sendto(build_ack(block_number), addr)

            if len(payload) < TFTP_BLOCK_SIZE:
                print(f"다운로드 완료: {filename}")
                file.close()
                return

    finally:
        sock.close()


def tftp_put(host: str, port: int, filename: str):
    if not os.path.exists(filename):
        print(f"에러: 로컬에 '{filename}' 파일이 없습니다.")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TFTP_TIMEOUT)

    try:
        req = build_request(OP_WRQ, filename)
        sock.sendto(req, (host, port))

        try:
            data, addr = sock.recvfrom(4 + 128)
        except socket.timeout:
            print("에러: WRQ 응답 timeout")
            return

        opcode = struct.unpack("!H", data[:2])[0]

        if opcode == OP_ERROR:
            error_code, msg = parse_error_packet(data)
            print(f"서버 ERROR({error_code}): {msg}")
            return

        if opcode != OP_ACK or struct.unpack("!H", data[2:4])[0] != 0:
            print("에러: WRQ ACK 수신 실패")
            return

        with open(filename, "rb") as f:
            current_block = 1

            while True:
                chunk = f.read(TFTP_BLOCK_SIZE)
                data_packet = build_data(current_block, chunk)

                for attempt in range(3):
                    sock.sendto(data_packet, addr)

                    try:
                        resp, addr2 = sock.recvfrom(4 + 128)
                        if struct.unpack("!H", resp[:2])[0] == OP_ACK and struct.unpack("!H", resp[2:4])[0] == current_block:
                            break
                    except socket.timeout:
                        if attempt == 2:
                            print(f"에러: 블록 {current_block} ACK timeout")
                            return

                if len(chunk) < TFTP_BLOCK_SIZE:
                    print(f"업로드 완료: {filename}")
                    return

                current_block += 1

    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(description="Simple TFTP client")
    parser.add_argument("host")
    parser.add_argument("command", choices=["get", "put"])
    parser.add_argument("filename")
    parser.add_argument("-p", "--port", type=int, default=TFTP_PORT)

    args = parser.parse_args()

    if args.command == "get":
        tftp_get(args.host, args.port, args.filename)
    else:
        tftp_put(args.host, args.port, args.filename)


if __name__ == "__main__":
    main()

</details>
