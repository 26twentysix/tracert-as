import argparse
import traceroute
import sys


def parse_args():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('-H', '--hostname', required=True, help='Target hostname')
    arg_parser.add_argument('-t', '--timeout', default=3, type=int, help='response timeout is seconds (default is 3)')
    arg_parser.add_argument('-T', '--tries', default=1, type=int, help='number of tries (default is 1)')
    res = arg_parser.parse_args()
    return res.hostname, res.timeout, res.tries


if __name__ == '__main__':
    host, timeout, tries = parse_args()
    trace = traceroute.Traceroute(timeout=timeout, tries=tries)
    try:
        trace.get_route(host)
    except PermissionError:
        print('Error: Аdministrator rights required')
        sys.exit(1)