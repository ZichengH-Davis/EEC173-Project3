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
WINDOW_SIZE = 1

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
    i = 0
    while i < 300: #data:
        if len(data) < MSS:
            # If the remainder of data is not a full chunk of size MSS
            # Just read what's left
            chunks.append(data[0:])
        else:
            # Still has more than MSS amount of data
            chunks.append(data[:MSS])
        
        data = data[MSS:]
        i += 1
    
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
    for pair in delay_tracker.values():
        delays.append(pair[1] - pair[0])
        #print(f"Start: {pair[0]}, Finish: {pair[1]}")
    #delays = delays[0:len(delays)-1]
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

        size = WINDOW_SIZE

        #Tahoe Variables
        threshold = 64
        duplicate = 1
        #region = 0  #0 = exponential, 1 = linear
        # Until every packet has been sent
        srtt = None # smoothed RTT
        base_rtt = None # minimum RTT seen
        last_send_time = 0.0 # time of last packet send
        ALPHA = 0.125
        
        

        last_acked_id = None 
        while begin_index < total_packets:
            
            packets_sent = 0
            while (next_index < total_packets) and packets_sent < size: 
                # Create the packet and send to reciever
                id, payload = transfers[next_index]
                pkt = make_packet(id, payload)

                #let the program wait and get last send time of the packet
                last_send_time = pace_before_send(size, srtt, last_send_time) 

                print(f"Sending seq={id}, bytes={len(payload)}")
                sock.sendto(pkt, addr)

                # Start the timer for that specific packet,
                # and initialize end time to 0
                delay_tracker[id] = [time.time(), 0.0]

                # Update for next packet
                next_index += 1
                packets_sent = next_index - begin_index


            try:
                # Take the packet and extract info from it
                pkt, _ = sock.recvfrom(PACKET_SIZE)
                id, message = parse_ack(pkt)
                print(f"Received {message.strip()} for ack_id={id}")
                

                # Send the final message to close out
                if message.startswith("fin"):
                    fin_ack = make_packet(id, b"FIN/ACK")
                    sock.sendto(fin_ack, addr)
                    finished_time = time.time()
                    for pair in delay_tracker.values():
                        if pair[1]==0.0:
                            pair[1] = finished_time
                    print_metrics(total_bytes, (time.time()- start), delay_tracker)
                    return
                
                # If the message starts with "ack" then we do the two things
                if message.startswith("ack"):
                    # Go through each packet within window and update ack times

                    for i in range(begin_index, begin_index + size):
                        if i < len(transfers) - 1:
                            # Just care about the seq_id, and not the actual payload
                            seq_id, _ = transfers[i]
                            
                            # Update the time ack was recieved ONLY if:
                            #   1) seq_id is less than the acknowledged id
                            #   2) time within delay_tracker has not been updated previously
                            if seq_id < id and seq_id in delay_tracker and delay_tracker[seq_id][1] == 0.0:
                                ack_time = time.time()
                                send_time = delay_tracker[seq_id][0]
                                delay_tracker[seq_id][1] = ack_time

                                sample_rtt = ack_time - send_time

                                if srtt is None:
                                    srtt = sample_rtt
                                    base_rtt = sample_rtt
                                else:
                                    srtt = (1 - ALPHA) * srtt + ALPHA * sample_rtt
                                    if base_rtt is None:
                                        base_rtt = sample_rtt
                                    else:
                                        base_rtt = min(base_rtt, sample_rtt)

                        else:
                            break

                    
                    if last_acked_id is None or id > last_acked_id:
                        last_acked_id = id
                        duplicate = 0

                        if(size <= threshold):
                            size = 2 * size
                        else: size = size + 1

                    elif id == last_acked_id:
                        duplicate += 1
                        if duplicate == 3:
                            # --- RENO BEHAVIOR: fast retransmit + cwnd -> ssthresh --- #
                            threshold = (int)(size/2)
                            threshold = max(threshold, 1)
                            size = threshold

                            print(f"3 dup acks at {id}, new threshold={threshold}, new window={size}")  # *** CHANGED

                            # Fast retransmit: resend first unacked packet immediately  # *** NEW
                            resend_id, resend_payload = transfers[begin_index]
                            pkt_retx = make_packet(resend_id, resend_payload)

                            last_send_time = pace_before_send(size, srtt, last_send_time)

                            print(f"Fast retransmit seq={resend_id}, bytes={len(resend_payload)}")
                            sock.sendto(pkt_retx, addr)


                        # Optional (very small) "fast recovery" window inflation:   # *** NEW (optional Reno flavor)
                        elif duplicate > 3:
                            size += 1   # grow window slightly for each extra dup-ack  # *** NEW

                    # Now we can slide the window finally
                    # Just make sure not to extend past total_packets
                    # The ack_id indicates that all previous stuff was acknowledged
                    while begin_index < total_packets and transfers[begin_index][0] < id:
                        begin_index += 1


            except socket.timeout:
                # If a timeout is hit then just resend the whole window again
                #   Use next_index to avoid having to check for out of bounds indexing
                
                threshold = (int)(size/2)
                threshold = max(threshold, 1)
                size = 1
                next_index = begin_index

                # 'id' might not be defined here; use first-unacked seq instead  # *** CHANGED
                base_id, _ = transfers[begin_index]                               # *** CHANGED
                print(f"timeout at {base_id}, new threshold at {threshold}")      # *** CHANGED

                # Create the packet and send to receiver
                # Only difference from prior is that we shouldn't restart timer
                id, payload = transfers[begin_index]   # *** CHANGED (was transfers[i], i not defined reliably)
                pkt = make_packet(id, payload)

                last_send_time = pace_before_send(size, srtt, last_send_time)

                print(f"Resending seq={id}, bytes={len(payload)}")
                sock.sendto(pkt, addr)

            # Now we can just wait to recieve back the final FIN message
        while True:
            pkt, _ = sock.recvfrom(PACKET_SIZE)
            id, message = parse_ack(pkt)
            delay_tracker[id][1] = time.time()

            if message.startswith("fin"):
                finished_time = time.time()
                final_ack = make_packet(id, b"FIN/ACK")
                sock.sendto(final_ack, addr)
                print("Finished final")
                # Now just call final calls to calculate metrics
                for pair in delay_tracker.values():
                    if pair[1] == 0.0:
                        pair[1] = finished_time

                print_metrics(total_bytes, (time.time()- start), delay_tracker)
                return
        
        
            
def pace_before_send(cwnd: int, srtt: float | None, last_send_time: float) -> float:
    now = time.time()

    # If we don't have an RTT estimate yet or window is invalid, just send immediately
    if srtt is None or cwnd <= 0:
        return now

    gap = srtt / cwnd
    elapsed = now - last_send_time

    if elapsed < gap:
        time.sleep(gap - elapsed)
        now = time.time()

    return now

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Skeleton sender hit an error: {exc}", file=sys.stderr)
        sys.exit(1)
