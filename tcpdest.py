#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# tcpdest   Summarize TCP bytes send to different subnets.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpdest [-h] [-J] [[-S] ...subnets]
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# This is an adaptation of tcptop from the original bcc/tools, written
# by Brendan Gregg
#
# WARNING: This traces all send at the TCP level, and while it
# summarizes data in-kernel to reduce overhead, there may still be some
# overhead at high TCP send/receive rates (eg, ~13% of one CPU at 100k TCP
# events/sec. This is not the same as packet rate: funccount can be used to
# count the kprobes below to find out the TCP rate). Test in a lab environment
# first. If your send rate is low (eg, <1k/sec) then the overhead is
# expected to be negligible.
#
# Copyright 2017 Rodrigo Manyari
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 03-Oct-2017   Rodrigo Manyari   Created this based on tcptop.

import argparse
import json
import logging
import struct
import socket
from bcc import BPF
from time import sleep

# arguments
examples = """examples:
    ./tcpdest                              # trace TCP send to all subnets
    ./tcpdest -s kb                        # trace TCP send to all subnets
                                           # aggregated in kb
    ./tcpdest -S 10.80.0.0/24,10.80.1.0/24 # trace TCP send and groups the
                                           # aggregated bytes by subnet. By
                                           # default 0.0.0.0/0 is added at
                                           # runtime
    ./tcpdest -J                           # format the output in JSON
"""
parser = argparse.ArgumentParser(
    description="Summarize TCP send and aggregate by subnet",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-v", "--verbose", action="store_true",
    help="output debug statements")
parser.add_argument("-J", "--json", action="store_true",
    help="format output in JSON")
parser.add_argument("-S", "--subnets",
    help="comma separated list of subnets")
parser.add_argument("-I", "--interval", type=int, default=1,
    help="output interval, in seconds (default 1)")
parser.add_argument("-s", "--size", default="b",
    help="size of aggregations, supported values are b, kb, mb, gb")
args = parser.parse_args()

level = logging.INFO
if args.verbose:
    level = logging.DEBUG

logging.basicConfig(level=level)

logging.debug("Starting with the following args:")
logging.debug(args)

# args checking
if int(args.interval) <= 0:
    logging.error("Invalid interval, must be > 0. Exiting.")
    exit(1)
else:
    args.interval = int(args.interval)

# map of supported sizes
sizes = {
    "b": pow(1024, 0),
    "kb": pow(1024, 1),
    "mb": pow(1024, 2),
    "gb": pow(1024, 3)
}

if args.size in sizes:
    args.size = sizes[args.size] # let's swap the string value by 
                                 # actual numeric value
else:
    logging.error("size [%s] is not supported. See --help to get the list of supported size(s)" % args.size)
    exit(1)

# define the basic structure of the BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct index_key_t {
  u32 index;
};

BPF_HASH(ipv4_send_bytes, struct index_key_t);

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{
    u16 family = sk->__sk_common.skc_family;
    u64 *val, zero = 0;

    if (family == AF_INET) {
        u32 dst = sk->__sk_common.skc_daddr;
        unsigned categorized = 0;
        __SUBNETS__
    }
    return 0;
}
"""


# Takes in a mask and returns the integer equivalent
# e.g.
# mask_to_int(8) returns 4278190080
def mask_to_int(n):
    return ((1<<n) - 1) << (32 - n)

# Takes in a list of subnets and returns a list
# of tuple-3 containing:
# - The subnet info at index 0
# - The addr portion as an int at index 1
# - The mask portion as an int at index 2
#
# The last tuple-3 in the list will always
# be [0.0.0.0/0, 0, 0] which is the catch
# all subnet
#
# e.g.
# parse_subnets([10.10.0.0/24]) returns
# [
#   ['10.10.0.0/25', 168427520, 4294967040],
#   ['0.0.0.0/0', 0, 0]
# ]
def parse_subnets(subnets):
    all_subnets = subnets + ["0.0.0.0/0"]
    m = []
    for s in all_subnets:
        parts = s.split("/")
        netaddr_int = struct.unpack("!I", socket.inet_aton(parts[0]))[0]
        mask_int = mask_to_int(int(parts[1]))
        m.append([s, netaddr_int, mask_int])
    return m

def generate_bpf_subnets(subnets):
    template = """
        if (!categorized && (__NET_ADDR__ & __NET_MASK__) == (dst & __NET_MASK__)) {
          struct index_key_t key = {.index = __POS__};
          val = ipv4_send_bytes.lookup_or_init(&key, &zero);
          categorized = 1;
          (*val) += size;
        }
    """
    bpf = ''
    for i,s in enumerate(subnets):
        branch = template
        branch = branch.replace("__NET_ADDR__", str(s[1]))
        branch = branch.replace("__NET_MASK__", str(s[2]))
        branch = branch.replace("__POS__", str(i))
        bpf += branch
    return bpf

subnets = []
if args.subnets:
    subnets = args.subnets.split(",")

subnets = parse_subnets(subnets)

logging.debug("Packets are going to be categories in the following subnets:")
logging.debug(subnets)


bpf_subnets = generate_bpf_subnets(subnets)

# initialize BPF
bpf_text = bpf_text.replace("__SUBNETS__", bpf_subnets)

logging.debug("Done preprocessing the BPF program, this is what will actually get executed:")
logging.debug(bpf_text)

b = BPF(text=bpf_text)

ipv4_send_bytes = b["ipv4_send_bytes"]

logging.debug("Tracing... Output every %d secs. Hit Ctrl-C to end" % args.interval)

# output
exiting = 0
while (1):

    try:
        sleep(args.interval)
    except KeyboardInterrupt:
        exiting = 1

    # IPv4:  build dict of all seen keys
    keys = ipv4_send_bytes
    for k, v in ipv4_send_bytes.items():
        if k not in keys:
            keys[k] = v

    # to hold json data
    data = {}

    # output
    for k, v in reversed(sorted(keys.items(), key=lambda keys: keys[1].value)):
        send_bytes = 0
        if k in ipv4_send_bytes:
            send_bytes = int(ipv4_send_bytes[k].value)
        subnet = subnets[k.index][0]
        send = send_bytes / float(args.size)
        if args.json:
            data[subnet] = send
        else:
            print("%-21s %6d" % (subnet, send))

    if args.json:
        print(json.dumps(data))

    ipv4_send_bytes.clear()
    
    if exiting:
        exit(0)
