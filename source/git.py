"""
Written by Daniel Sungju Kwon

Execute git log/show commands on remote source server
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


def git():
    # Parse command line arguments manually to support git-style options
    args = sys.argv[1:] if __name__ == '__main__' else exec_crash_command("set").split()[1:]

    if len(args) == 0:
        print_help()
        return

    # Determine subcommand (log or show)
    subcommand = args[0]

    if subcommand not in ['log', 'show']:
        print("Error: Invalid subcommand '%s'" % subcommand)
        print("Usage: git <log|show> [options]")
        print("Try 'git log --help' or 'git show --help'")
        return

    # Parse options
    repos = ''
    timeout = 3600
    verbose = False
    all_versions = False
    git_options = []
    remaining_args = args[1:]

    i = 0
    while i < len(remaining_args):
        arg = remaining_args[i]

        if arg == '--all':
            all_versions = True
            i += 1
            continue
        elif arg == '--repos':
            if i + 1 < len(remaining_args):
                repos = remaining_args[i + 1]
                i += 2
                continue
            else:
                print("Error: --repos requires an argument")
                return
        elif arg.startswith('--repos='):
            repos = arg.split('=', 1)[1]
            i += 1
            continue
        elif arg == '--timeout':
            if i + 1 < len(remaining_args):
                timeout = int(remaining_args[i + 1])
                i += 2
                continue
            else:
                print("Error: --timeout requires an argument")
                return
        elif arg.startswith('--timeout='):
            timeout = int(arg.split('=', 1)[1])
            i += 1
            continue
        elif arg == '--verbose':
            verbose = True
            i += 1
            continue
        elif arg == '--help' or arg == '-h':
            print_help_for_subcommand(subcommand)
            return
        else:
            # Pass through to git
            git_options.append(arg)
            i += 1

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
        'subcommand': subcommand,
        'git_options': ' '.join(git_options),
        'repos': repos,
        'verbose': str(verbose),
        'kernel_version': kernel_ver,
        'all_versions': str(all_versions)
    }

    # Make API request
    api_url = server_url + '/api/git'

    try:
        if verbose:
            print("Executing: git %s %s" % (subcommand, ' '.join(git_options)))
            print("Connecting to: %s" % api_url)
            print("Timeout: %d seconds (%d minutes)" % (timeout, timeout // 60))

        response = r.post(api_url, data=data, timeout=timeout)

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


def print_help():
    print("Usage: git <subcommand> [options]")
    print("")
    print("Subcommands:")
    print("  log        Search git log (supports git log options, default: --max-count=1)")
    print("  show       Show commit details (supports git show options)")
    print("")
    print("Common options:")
    print("  --repos=<repos>    Comma-separated list of repos to search (e.g., rhel9,linux,upstream)")
    print("  --timeout=<secs>   Request timeout in seconds (default: 3600)")
    print("  --verbose          Show verbose output")
    print("  --all              Show all commit versions (default: only commits >= current kernel version)")
    print("  --help, -h         Show this help")
    print("")
    print("Examples:")
    print("  git log -Sclip_push --max-count=5")
    print("  git show abc123def --stat")
    print("  git log -Sinit_new_ldt --repos=rhel9,upstream")
    print("  git show HEAD~3 --repos=linux")


def print_help_for_subcommand(subcommand):
    if subcommand == 'log':
        print("Usage: git log [git-log-options]")
        print("")
        print("Search git log in remote kernel source repositories.")
        print("Supports all standard git log options.")
        print("")
        print("Common options:")
        print("  -S<string>         Search for commits that add/remove the string (pickaxe)")
        print("  --grep=<pattern>   Search commit messages for pattern")
        print("  --max-count=<n>    Limit number of commits to show (default: 1)")
        print("  --stat             Show diffstat")
        print("  --oneline          Show compact one-line format")
        print("  --repos=<repos>    Search additional repositories (e.g., rhel9,linux)")
        print("  --all              Show all commit versions (default: only commits >= current kernel version)")
        print("")
        print("Examples:")
        print("  git log -Sclip_push --max-count=5")
        print("  git log --grep=\"memory leak\" --since=\"2024-01-01\"")
        print("  git log -Sinit_new_ldt --stat --repos=rhel9,upstream")
    elif subcommand == 'show':
        print("Usage: git show [git-show-options] <commit>")
        print("")
        print("Show commit details from remote kernel source repositories.")
        print("Supports all standard git show options.")
        print("")
        print("Common options:")
        print("  --stat             Show diffstat only")
        print("  --name-only        Show only names of changed files")
        print("  --pretty=<format>  Format output (oneline, short, medium, full)")
        print("  --repos=<repo>     Specify repository to search (e.g., rhel9, linux)")
        print("  --all              Show all commit versions (default: only commits >= current kernel version)")
        print("")
        print("Examples:")
        print("  git show abc123def")
        print("  git show HEAD~3 --stat")
        print("  git show v5.10..v5.11 --oneline --repos=upstream")


if __name__ == '__main__':
    git()
