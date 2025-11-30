#!/usr/bin/env python3


# Adapted from our sender_stop_and_wait.py and sender.py from Week 7 discussion
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
#MAX_TIMEOUTS = 5

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


def print_metrics(total_bytes: int, duration: float, delay_tracker) -> None:
    throughput = total_bytes / duration

    # To calculate per packet delay, start timer as soon as packet is sent for the very first time (not resends) 
    # and stop the timer when the acknowledgement for that packet is recieved

    # To measure jitter, need to get the average value of the difference 
    # between the packet delays of two successive packets

    delays = []
    # Iterate through start/stop times and calculate delays
    for _, pair in delay_tracker:
        delays.append(pair[1] - pair[0])

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

    # JUST KEEP TRACK OF DELAYS WITHIN ACKOWLEDGEMENT DICTIONARY
    # Tracking the delays (which is also used to track jitter)
    # On stand by, haven't quite figured that out. Overhaul of bookeeping
    # delays = []

    total_bytes = 0
    seq = 0
    for chunk in demo_chunks:
        total_bytes += len(chunk)
        transfers.append((seq, chunk))
        seq += len(chunk)

    # EOF marker
    transfers.append((seq, b""))
    #total_bytes = sum(len(chunk) for chunk in demo_chunks)

    print(f"Connecting to receiver at {HOST}:{PORT}")
    print(
        f"Demo transfer will send {total_bytes} bytes across {len(demo_chunks)} packets (+EOF)."
    )
    # Reset seq id to be used for later
    #seq = 0
    # Initial start time
    start = time.time()
    
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(ACK_TIMEOUT)
        addr = (HOST, PORT)

        # Window Related Indexes
        total_packets = len(transfers)
        begin_index = 0                 # First unacked packet
        next_index = 0                  # Keep track of next packet being sent 
                                        # (Helpful during timeouts/ resending the window)
        

        # Dictionary to keep track of which packets we have recieved acks for
        # Stored as: ack_id : (start time, ack time)
        # Makes it easier since have to track multiple delays for all packets
        delay_tracker = {}
    
        # Until every packet has been sent
        while begin_index < total_packets:
            
            # Call helper function to initialize a window with all the necessary packets
            #packets, acks = window_packets_helper(transfers, begin_index, acks)
            '''
            for pkt in packets:
                sock.sendto(pkt,addr)
                seq += MSS
            '''

            '''
            # ----------- SENDING WINDOW PACKETS ------------

            # Keep sending packets as long as:
            #   1) We don't try sending more packets beyond what exists
            #   2) Don't send anymore than the window size
            '''
            
            # Helpful for while loop
            packets_sent = 0
            while (next_index < total_packets) and packets_sent < WINDOW_SIZE: 
                # Create the packet and send to reciever
                id, payload = transfers[next_index]
                pkt = make_packet(id, payload)

                print(f"Sending seq={id}, bytes={len(payload)}")
                sock.sendto(pkt, addr)

                # Start the timer for that specific packet,
                # and initialize end time to 0
                delay_tracker[id] = (time.time(), 0.0)

                # Update for next packet
                next_index += 1
                packets_sent = next_index - begin_index


            '''
            #  ------------ RECIEVE PACKET ACKNOWLEDGEMENT OR END ------------

            # First recieve and see if it's a fin message
            #   Something happened and server trying to terminate

            # Then see if it's an acknowledgement and if it is:
            # 1) Update the time when the acknowledgement was recieved
            # 2) Move that sliding window up until most recent acknowledgement
            

            # If there was a TIMEOUT 
            #   Then start from beginning of the window and send packets again 
            '''

            
            try:
                # Take the packet and extract info from it
                pkt, _ = sock.recvfrom(PACKET_SIZE)
                id, message = parse_ack(pkt)
                print(f"Received {message.strip()} for ack_id={id}")

                # Send the final message to close out
                if message.startswith("fin"):
                    fin_ack = make_packet(id, b"FIN/ACK")
                    sock.sendto(fin_ack, addr)
                    break
                
                # If the message starts with "ack" then we do the two things
                if message.startswith("ack"):
                    # Go through each packet within window and update ack times
                    for i in range(begin_index, begin_index + WINDOW_SIZE):
                        # Just care about the seq_id, and not the actual payload
                        seq_id, _ = transfers[i]
                        
                        # Update the time ack was recieved ONLY if:
                        #   1) seq_id is less than the acknowledged id
                        #   2) time within delay_tracker has not been updated previously
                        if seq_id < id and seq_id not in delay_tracker:
                            delay_tracker[seq_id][1] = time.time()

                    # Now we can slide the window finally
                    # Just make sure not to extend past total_packets
                    # The ack_id indicates that all previous stuff was acknowledged
                    while begin_index < total_packets and transfers[begin_index][0] < id:
                        begin_index += 1


            except sock.timeout:
                # If a timeout is hit then just resend the whole window again
                #   Use next_index to avoid having to check for out of bounds indexing
                for i in range(begin_index,next_index):
                    # Create the packet and send to reciever
                    # Only difference from prior is that we shouldn't restart timer
                    id, payload = transfers[i]
                    pkt = make_packet(id, payload)

                    print(f"Resending seq={id}, bytes={len(payload)}")
                    sock.sendto(pkt, addr)

            # Now we can just wait to recieve back the final FIN message
            while True:
                pkt, _ = sock.recvfrom(PACKET_SIZE)
                id, message = parse_ack(pkt)
                if message.startswith("fin"):
                    final_ack = make_packet(id, b"FIN/ACK")
                    sock.sendto(final_ack, addr)
                    
                    # Now just call final calls to calculate metrics
                    print_metrics(total_bytes, (time.time()- start), delay_tracker)
                    return
        
        
            

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Skeleton sender hit an error: {exc}", file=sys.stderr)
        sys.exit(1)
