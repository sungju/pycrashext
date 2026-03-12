"""
Written by Daniel Sungju Kwon

Search git log in remote source server for matching commits
"""

from pykdump.API import *
from LinuxDump import Tasks

import sys
import os
from os.path import expanduser
import base64
import requests as r

import crashcolor
import crashhelper


def gitsearch():
    op = OptionParser()
    op.add_option('-l', '--lines', dest='lines', default=20,
                  action='store', type='int',
                  help='Maximum lines to show per commit (default: 20, use 0 for all)')

    op.add_option('-m', '--maxmatch', dest='maxmatch', default=5,
                  action='store', type='int',
                  help='Maximum matching commits to show (default: 5, use 0 for all)')

    op.add_option('-e', '--extraversion', dest='extraversion', default='',
                  action='store', type='string',
                  help='Additional directories to search (comma-separated, e.g., rhel9,rhel10,linux)')

    op.add_option('-v', '--verbose', dest='verbose', default=False,
                  action='store_true',
                  help='Show verbose output')

    op.add_option('--context', dest='context', default=False,
                  action='store_true',
                  help='Show file context in patches')

    op.add_option('-t', '--timeout', dest='timeout', default=3600,
                  action='store', type='int',
                  help='Request timeout in seconds (default: 3600 = 1 hour)')

    op.add_option('-c', '--commit', dest='commit', default='',
                  action='store', type='string',
                  help='Show full content of a specific commit ID')

    (o, args) = op.parse_args()

    # For --commit option, no search pattern needed
    if o.commit:
        search_pattern = ''
    elif len(args) == 0:
        op.print_help()
        return
    else:
        search_pattern = ' '.join(args)

    # Check if CRASHEXT_SERVER is configured
    try:
        server_url = os.environ['CRASHEXT_SERVER']
    except:
        print("CRASHEXT_SERVER environment variable not configured")
        print("\nPlease set it to your remote source server URL:")
        print("  export CRASHEXT_SERVER=http://your-server:5000")
        return

    # Get kernel version for context (same approach as edis.py)
    kernel_ver = "unknown"
    try:
        sys_output = exec_crash_command("sys")
        for line in sys_output.splitlines():
            words = line.split()
            if len(words) >= 2 and words[0] == "RELEASE:":
                kernel_ver = words[1]
                break
    except Exception as e:
        print("Warning: Could not detect kernel version: %s" % str(e))
        kernel_ver = "unknown"

    # Prepare request data
    data = {
        'pattern': search_pattern,
        'lines': o.lines,
        'maxmatch': o.maxmatch,
        'extraversion': o.extraversion,
        'verbose': o.verbose,
        'context': o.context,
        'kernel_version': kernel_ver,
        'commit': o.commit
    }

    # Make API request
    api_url = server_url + '/api/gitsearch'

    try:
        if o.verbose:
            print("Searching for: %s" % search_pattern)
            print("Connecting to: %s" % api_url)
            print("Timeout: %d seconds (%d minutes)" % (o.timeout, o.timeout // 60))
            print("Note: This may take several minutes for git log searches...")

        # Use a long timeout for git log searches which can be slow,
        # especially when searching multiple RHEL versions and large repositories
        response = r.post(api_url, data=data, timeout=o.timeout)

        if response.status_code == 200:
            print(response.text)
        else:
            print("Error: Server returned status code %d" % response.status_code)
            print(response.text)

    except r.exceptions.RequestException as e:
        print("\nServer is not reachable.")
        print("Server address is <%s>" % api_url)
        print("\nError: %s" % str(e))
        print("\nMake sure:")
        print("  1. CRASHEXT_SERVER is set correctly")
        print("  2. The remote server is running")
        print("  3. Network connectivity is available")
    except Exception as e:
        print("Unexpected error: %s" % str(e))


if __name__ == '__main__':
    gitsearch()
