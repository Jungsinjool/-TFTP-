#!/usr/bin/env python3
import argparse
import os
import socket
import struct
import sys

# 기본 TFTP 설정
TFTP_PORT = 69                 # TFTP 기본 포트는 UDP 69
TFTP_TIMEOUT = 5.0             # 서버 응답 대기 시간
TFTP_BLOCK_SIZE = 512          # TFTP 데이터 블록 기본 크기

# TFTP Opcode 정의 (프로토콜 스펙)
OP_RRQ = 1     # Read Request  (다운로드)
OP_WRQ = 2     # Write Request (업로드)
OP_DATA = 3    # DATA 전송
OP_ACK = 4     # ACK 응답
OP_ERROR = 5   # 오류 패킷


def build_request(opcode: int, filename: str, mode: str = "octet") -> bytes:
    """
    RRQ/WRQ 패킷 생성 함수
    TFTP 패킷 구조:
        2 byte opcode | filename | 0 | mode | 0

    opcode : RRQ=1 또는 WRQ=2
    filename : 전송할 파일 이름
    mode : 'octet' (바이너리 전송)
    """
    return struct.pack("!H", opcode) + filename.encode() + b'\x00' + mode.encode() + b'\x00'


def build_ack(block_number: int) -> bytes:
    """
    ACK 패킷 생성
    구조: 2 byte opcode(4) | 2 byte block number
    """
    return struct.pack("!HH", OP_ACK, block_number)


def build_data(block_number: int, data: bytes) -> bytes:
    """
    DATA 패킷 생성
    구조: 2 byte opcode(3) | 2 byte block number | 실제 데이터
    """
    return struct.pack("!HH", OP_DATA, block_number) + data


def parse_error_packet(packet: bytes):
    """
    서버로부터 ERROR 패킷을 받았을 때 코드/메시지를 파싱하는 함수
    ERROR 패킷 구조:
        2 byte opcode(5) | 2 byte error_code | error_message | 0
    """
    _, error_code = struct.unpack("!HH", packet[:4])
    msg = packet[4:-1].decode(errors="ignore")
    return error_code, msg


def tftp_get(host: str, port: int, filename: str):
    """
    GET 요청 처리 함수 (서버 → 클라이언트 다운로드)
    프로세스:
      1) RRQ 전송
      2) 서버의 DATA(1) 수신 후 ACK 전송
      3) 블록 번호 증가시키며 반복
      4) 마지막 블록이 512바이트 미만이면 종료
    """
    # 로컬에 같은 파일 존재하면 덮어쓰지 않고 에러 처리
    if os.path.exists(filename):
        print(f"에러: 로컬에 이미 '{filename}' 파일이 존재합니다. (File already exists)")
        return

    # UDP 소켓 생성
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TFTP_TIMEOUT)

    try:
        # RRQ 패킷 생성 후 전송
        req = build_request(OP_RRQ, filename)
        sock.sendto(req, (host, port))

        file = open(filename, "wb")         # 다운로드 파일 생성
        expected_block = 1                  # 첫 DATA 블록은 Block #1

        while True:
            try:
                data, addr = sock.recvfrom(4 + TFTP_BLOCK_SIZE)
            except socket.timeout:
                print("에러: RRQ 또는 DATA에 대한 서버 응답이 없습니다. (timeout)")
                file.close()
                os.remove(filename)         # 불완전 파일 삭제
                return

            opcode = struct.unpack("!H", data[:2])[0]

            # 서버에서 ERROR 패킷 수신
            if opcode == OP_ERROR:
                error_code, msg = parse_error_packet(data)
                print(f"서버 ERROR({error_code}): {msg}")
                file.close()
                os.remove(filename)
                return

            # 정상적인 DATA 패킷인지 확인
            if opcode != OP_DATA:
                print(f"에러: 예상치 못한 opcode 수신: {opcode}")
                file.close()
                os.remove(filename)
                return

            block_number = struct.unpack("!H", data[2:4])[0]
            payload = data[4:]

            # 예상된 블록이면 파일에 쓰기
            if block_number == expected_block:
                file.write(payload)
                ack = build_ack(block_number)
                sock.sendto(ack, addr)
                expected_block += 1
            else:
                # 중복 DATA 패킷 → ACK만 재전송
                ack = build_ack(block_number)
                sock.sendto(ack, addr)

            # 마지막 DATA 블록 (블록 크기 < 512)
            if len(payload) < TFTP_BLOCK_SIZE:
                print(f"다운로드 완료: {filename}")
                file.close()
                return

    finally:
        sock.close()


def tftp_put(host: str, port: int, filename: str):
    """
    PUT 요청 처리 함수 (클라이언트 → 서버 업로드)
    프로세스:
      1) 로컬 파일이 존재하는지 확인
      2) WRQ 전송
      3) 서버에서 ACK(0) 수신
      4) DATA 블록 1부터 512바이트씩 전송
      5) ACK를 받으면 다음 블록 전송
    """
    if not os.path.exists(filename):
        print(f"에러: 로컬에 '{filename}' 파일이 없습니다. (File not found)")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TFTP_TIMEOUT)

    try:
        req = build_request(OP_WRQ, filename)
        sock.sendto(req, (host, port))

        # WRQ 후 서버의 ACK(0) 대기
        try:
            data, addr = sock.recvfrom(4 + 128)
        except socket.timeout:
            print("에러: WRQ에 대한 서버 응답이 없습니다. (timeout)")
            return

        opcode = struct.unpack("!H", data[:2])[0]

        if opcode == OP_ERROR:
            error_code, msg = parse_error_packet(data)
            print(f"서버 ERROR({error_code}): {msg}")
            return

        if opcode != OP_ACK:
            print(f"에러: WRQ 이후 ACK가 아닌 opcode 수신: {opcode}")
            return

        block_number = struct.unpack("!H", data[2:4])[0]

        # Block #0 ACK이 아닌 경우 이상
        if block_number != 0:
            print("에러: WRQ 응답의 블록 번호가 0이 아닙니다.")
            return

        # 파일 전송 시작
        with open(filename, "rb") as f:
            current_block = 1

            while True:
                chunk = f.read(TFTP_BLOCK_SIZE)
                data_packet = build_data(current_block, chunk)

                # ACK 대기 + 최대 3회 재전송
                for attempt in range(3):
                    sock.sendto(data_packet, addr)

                    try:
                        resp, addr2 = sock.recvfrom(4 + 128)
                        resp_opcode = struct.unpack("!H", resp[:2])[0]

                        if resp_opcode == OP_ERROR:
                            error_code, msg = parse_error_packet(resp)
                            print(f"서버 ERROR({error_code}): {msg}")
                            return

                        if resp_opcode != OP_ACK:
                            print("에러: ACK 대신 다른 opcode 수신")
                            return

                        ack_block = struct.unpack("!H", resp[2:4])[0]

                        if ack_block == current_block:
                            break   # 정상 ACK → 다음 블록 전송
                    except socket.timeout:
                        # 3번 시도 후에도 ACK를 못 받으면 중단
                        if attempt == 2:
                            print(f"에러: DATA 블록 {current_block}에 대한 ACK timeout (3회 실패)")
                            return

                # 마지막 블록 전송 후 종료
                if len(chunk) < TFTP_BLOCK_SIZE:
                    print(f"업로드 완료: {filename}")
                    return

                current_block += 1

    finally:
        sock.close()


def main():
    """
    명령행 인자 처리 및 실행 제어 함수
    형식:
        ./mytftp host [-p port] [get|put] filename
    """
    parser = argparse.ArgumentParser(description="Simple TFTP client (get/put, octet mode)")
    parser.add_argument("host", help="TFTP 서버 호스트 (도메인 또는 IP)")
    parser.add_argument("command", choices=["get", "put"], help="명령: get 또는 put")
    parser.add_argument("filename", help="전송할 파일 이름")
    parser.add_argument("-p", "--port", type=int, default=TFTP_PORT, help="TFTP 서버 포트 (기본 69)")

    args = parser.parse_args()

    if args.command == "get":
        tftp_get(args.host, args.port, args.filename)
    else:
        tftp_put(args.host, args.port, args.filename)


if __name__ == "__main__":
    main()
