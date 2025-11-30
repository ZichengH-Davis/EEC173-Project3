#!/usr/bin/env python3
"""
Minimal sender skeleton for ECS 152A project.

Purpose:
    - Send two demo packets (plus EOF marker) to verify your environment,
      receiver, and test scripts are wired up correctly.
    - Provide a tiny Stop-and-Wait style template students can extend.

Usage:
    ./test_sender.sh sender_skeleton.py [payload.zip]

Notes:
    - This is NOT a full congestion-control implementation.
    - It intentionally sends only a couple of packets so you can smoke-test
      the simulator quickly before investing time in your own sender.
    - Delay, jitter, and score calculations are hardcoded placeholders.
      Students should implement their own metrics tracking.
"""

from __future__ import annotations

import os
import socket
import sys
import time
from typing import List, Tuple

PACKET_SIZE = 1024
SEQ_ID_SIZE = 4
MSS = PACKET_SIZE - SEQ_ID_SIZE
ACK_TIMEOUT = 1.0
MAX_TIMEOUTS = 5

# Window Size given in project description
WINDOW_SIZE = 100

HOST = os.environ.get("RECEIVER_HOST", "127.0.0.1")
PORT = int(os.environ.get("RECEIVER_PORT", "5001"))


def load_payload_chunks() -> List[bytes]:
    """
    Reads the selected payload file (or falls back to file.zip) and returns
    up to two MSS-sized chunks for the demo transfer.
    """
    candidates = [
        os.environ.get("TEST_FILE"),
        os.environ.get("PAYLOAD_FILE"),
        "/hdd/file.zip",
        "file.zip",
    ]

    for path in candidates:
        if not path:
            continue
        expanded = os.path.expanduser(path)
        if os.path.exists(expanded):
            with open(expanded, "rb") as f:
                data = f.read()
            break
    else:
        print(
            "Could not find payload file (tried TEST_FILE, PAYLOAD_FILE, file.zip)",
            file=sys.stderr,
        )
        sys.exit(1)

    if not data:
        return [b"Hello from ECS152A!", b"Second packet from skeleton sender"]


    # TODO: THIS NEEDS TO CHANGE, ONLY PROVIDES TWO PACKETS AND NOT THE FULL FILE!!
    
    '''
    first = data[:MSS] or b"First chunk placeholder"
    second = data[MSS : 2 * MSS] or b"Second chunk placeholder"
    return [first, second]
    

    # Just write a loop that iterates until all of "data" has been read
    chunks = []
    file_size = len(data)
    i = 0
    while i*MSS < file_size:
        chunks.append(data[i*MSS : (i+1)*MSS])
        i += 1

    '''
    
    chunks = []
    # While there is still data to be read
    while data:
        if len(data) < MSS:
            # If the remainder of data is not a full chunk of size MSS
            # Just read what's left
            chunks.append(data[0:])
        else:
            # Still has more than MSS amount of data
            chunks.append(data[:MSS])
        
        data = data[MSS:]
    
    return chunks


def make_packet(seq_id: int, payload: bytes) -> bytes:
    return int.to_bytes(seq_id, SEQ_ID_SIZE, byteorder="big", signed=True) + payload


def parse_ack(packet: bytes) -> Tuple[int, str]:
    seq = int.from_bytes(packet[:SEQ_ID_SIZE], byteorder="big", signed=True)
    msg = packet[SEQ_ID_SIZE:].decode(errors="ignore")
    return seq, msg


def print_metrics(total_bytes: int, duration: float, delays: list) -> None:
    """
    Print transfer metrics in the format expected by test scripts.

    TODO: Students should replace the hardcoded delay/jitter/score values
    with actual calculated metrics from their implementation.
    """
    throughput = total_bytes / duration

    # To calculate per packet delay, start timer as soon as packet is sent for the very first time (not resends) 
    # and stop the timer when the acknowledgement for that packet is recieved

    # To measure jitter, need to get the average value of the difference 
    # between the packet delays of two successive packets

    # Placeholder values - students should calculate these based on actual measurements
    avg_delay = sum(delays)/len(delays) #0.0

    # Create a new list that has all jitters values
    jitters = []
    for i in range(1, len(delays)):
        jitters.append(abs(delays[i] - delays[i-1]))
    avg_jitter = sum(jitters)/len(jitters) #0.0
    
    score = (throughput/2000)+(15/avg_jitter)+(35/avg_delay) #0.0

    print("\nTransfer complete!")
    print(f"duration={duration:.3f}s throughput={throughput:.2f} bytes/sec")
    print(f"avg_delay={avg_delay:.6f}s avg_jitter={avg_jitter:.6f}s")
    print(f"{throughput:.7f},{avg_delay:.7f},{avg_jitter:.7f},{score:.7f}")


def main() -> None:
    demo_chunks = load_payload_chunks()
    transfers: List[Tuple[int, bytes]] = []

    # Tracking the delays (which is also used to track jitter)
    # On stand by, haven't quite figured that out. Overhaul of bookeeping
    # delays = []

    
    seq = 0
    for chunk in demo_chunks:
        transfers.append((seq, chunk))
        seq += len(chunk)

    # EOF marker
    transfers.append((seq, b""))
    total_bytes = sum(len(chunk) for chunk in demo_chunks)

    print(f"Connecting to receiver at {HOST}:{PORT}")
    print(
        f"Demo transfer will send {total_bytes} bytes across {len(demo_chunks)} packets (+EOF)."
    )
    # Reset seq id to be used for later
    seq = 0
    # Initial start time
    start = time.time()
    
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(ACK_TIMEOUT)
        addr = (HOST, PORT)

        # Window Indexe
        begin_index = 0

        while seq < len(transfers):
            

            # Dictionary to keep track of which packets we have recieved acks for
            acks = {}

            if len(transfers) >= WINDOW_SIZE:
                for seq_id, payload in transfers[begin_index:(begin_index+100)]:
                    pkt = make_packet(seq_id, payload)
                    acks[seq_id] = False
                    sock.sendto(pkt,addr)
                    seq += MSS
            else:
                for seq_id, payload in transfers[begin_index: ]:
                    pkt = make_packet(seq_id, payload)
                    acks[seq_id] = False
                    sock.sendto(pkt,addr)
                    seq += MSS

            while True:
                try:
                    packet, _ = sock.recvfrom(PACKET_SIZE)
                    seq_id, msg = parse_ack(packet)
                    acks[seq_id] = True
                    if all(acks.values()):
                        break
                except:
                    # One of the packets timed out, send out all that don't have acknowledgement
                    for failed_ids in [sid for sid in acks.keys() if not acks[sid]]:
                        seq_id, payload = transfers[failed_ids//PACKET_SIZE]
                        pkt = make_packet(seq_id, payload)
                        sock.sendto(pkt,addr)
        
                if msg.startswith("fin"):

                        #delays.append(time.time()-delay_start)

                        # Respond with FIN/ACK to let receiver exit cleanly
                        fin_ack = make_packet(seq_id, b"FIN/ACK")
                        sock.sendto(fin_ack, addr)
                        duration = max(time.time() - start, 1e-6)
                        print_metrics(total_bytes, duration,delays)
                        return



        '''
        for seq_id, payload in transfers:
            pkt = make_packet(seq_id, payload)
            print(f"Sending seq={seq_id}, bytes={len(payload)}")

            retries = 0

            # Start delay timer right before sending first packet
            delay_start = time.time()
            while True:
                sock.sendto(pkt, addr)

                try:
                    ack_pkt, _ = sock.recvfrom(PACKET_SIZE)
                except socket.timeout:
                    retries += 1
                    if retries > MAX_TIMEOUTS:
                        raise RuntimeError(
                            "Receiver did not respond (max retries exceeded)"
                        )
                    print(
                        f"Timeout waiting for ACK (seq={seq_id}). Retrying ({retries}/{MAX_TIMEOUTS})..."
                    )
                    continue

                ack_id, msg = parse_ack(ack_pkt)
                print(f"Received {msg.strip()} for ack_id={ack_id}")

                # TENTATIVELY STOP DELAY TIMER, (Don't yet know if correct)
                #delays.append(time.time()-delay_start)

                if msg.startswith("fin"):

                    delays.append(time.time()-delay_start)

                    # Respond with FIN/ACK to let receiver exit cleanly
                    fin_ack = make_packet(ack_id, b"FIN/ACK")
                    sock.sendto(fin_ack, addr)
                    duration = max(time.time() - start, 1e-6)
                    print_metrics(total_bytes, duration,delays)
                    return

                if msg.startswith("ack") and ack_id >= seq_id + len(payload):
                    delays.append(time.time()-delay_start)
                    break
                # Else: duplicate/stale ACK, continue waiting

        # Wait for final FIN after EOF packet
        while True:
            ack_pkt, _ = sock.recvfrom(PACKET_SIZE)
            ack_id, msg = parse_ack(ack_pkt)
            if msg.startswith("fin"):
                delays.append(time.time()-delay_start)

                fin_ack = make_packet(ack_id, b"FIN/ACK")
                sock.sendto(fin_ack, addr)
                duration = max(time.time() - start, 1e-6)
                print_metrics(total_bytes, duration,delays)
                return
        '''

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Skeleton sender hit an error: {exc}", file=sys.stderr)
        sys.exit(1)
