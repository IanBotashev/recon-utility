#!/usr/bin/env python3
import argparse
import sys
import threading
import nmap
import logging
import socket
import subprocess  # For executing a shell command
from ping3 import ping
from terminaltables import AsciiTable


DEFAULT_WEBSERVER_PORTS = [80, 443]


class ReconUtility:
    def __init__(self, target: str, verbose: bool, wordlist: bool):
        self.has_web_server = None
        if verbose:
            log_level = logging.DEBUG
        else:
            log_level = logging.INFO

        logging.basicConfig(format='[%(levelname)s] %(message)s', level=log_level)
        logging.info("Resolving host...")
        self.target = socket.gethostbyname(target)
        self.nm = nmap.PortScanner()
        self.wordlist = wordlist
        logging.info(f"recon-utility started on target '{self.target}'")

    def run(self):
        """
        Main entry point, takes a target.
        :return:
        """
        if not self.check_if_target_running():
            logging.critical("Target is not up.")
            exit()

        self.has_web_server = self.check_for_webserver()
        nmap_thread = threading.Thread(target=self.full_scan)
        gobuster_thread = threading.Thread(target=self.bust_dirs)

        logging.debug("Started nmap thread...")
        nmap_thread.start()
        logging.debug("Started gobuster thread...")
        gobuster_thread.start()

        nmap_thread.join()
        gobuster_thread.join()

    def check_if_target_running(self):
        """
        Returns True of False depending on if the host is reachable.
        :return:
        """
        return ping(self.target) is not None

    def check_for_webserver(self):
        """
        Checks if the target is running a webserver.
        :return:
        """
        has_server = False
        for test_port in DEFAULT_WEBSERVER_PORTS:
            self.nm.scan(self.target, str(test_port))
            temp_has_server = self.nm[self.target].tcp(test_port)['state'] == 'open'
            logging.debug(self.nm[self.target].tcp(test_port))
            if temp_has_server:
                has_server = temp_has_server
                logging.info(f"Target appears to have a web server ('{self.nm[self.target].tcp(test_port)['product']}') running on port {test_port}")

        if not has_server:
            logging.info("Target appears to NOT have any web server running.")

        return has_server

    def bust_dirs(self):
        """
        Runs gobuster.
        :return:
        """
        if self.wordlist is not None and self.has_web_server:
            result = subprocess.check_output(['gobuster', 'dir', '-u', self.target, '-w', self.wordlist])
            print(result.decode('ascii'))

    def full_scan(self):
        """
        Does a full scan on a target.
        :return:
        """
        table_data = [
            ['PORT', 'STATE', 'PRODUCT', 'SERVICE', 'EXTRA-INFO']
        ]
        self.nm.scan(self.target)
        for protocol in self.nm[self.target].all_protocols():
            ports = self.nm[self.target][protocol].keys()
            for port in ports:
                port_info = self.nm[self.target][protocol][port]
                table_data.append([f"{port}/{protocol}",
                                   port_info['state'],
                                   f"{port_info['product']} {port_info['version']}",
                                   port_info['name'],
                                   port_info['extrainfo']])

        print(AsciiTable(table_data).table)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="python3 recon.py",
                                     description="Simple utility to quickly enumerate a target.")
    parser.add_argument('target',
                        type=str)
    parser.add_argument('-v', '--verbose',
                        action='store_true')
    parser.add_argument('-w', '--wordlist',
                        action='store',
                        help='Wordlist for busting url. If specified, will try gobuster.')
    args = parser.parse_args(sys.argv[1:])
    try:
        ReconUtility(args.target, args.verbose, args.wordlist).run()
    except KeyboardInterrupt:
        logging.critical("Exiting...")
