"""
'git' command: run git log/show/find in remote kernel source repositories through the remoteapi server.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from pykdump.API import *
from LinuxDump import Tasks

import sys
import os
from os.path import expanduser
import base64
import urllib.request
import urllib.parse
import urllib.error

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

    if subcommand not in ['log', 'show', 'find']:
        print("Error: Invalid subcommand '%s'" % subcommand)
        print("Usage: git <log|show|find> [options]")
        print("Try 'git log --help', 'git show --help' or 'git find --help'")
        return

    # Parse options
    repos = ''
    timeout = 3600
    verbose = False
    all_versions = False
    git_options = []
    remaining_args = args[1:]

    # 'find' has its own option set and is dispatched separately
    if subcommand == 'find':
        find(remaining_args)
        return

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
    server_url = get_server_url()
    if server_url is None:
        return

    # Get kernel version for context (same approach as edis.py)
    kernel_ver = get_kernel_version()

    # Prepare request data
    data = {
        'subcommand': subcommand,
        'git_options': ' '.join(git_options),
        'repos': repos,
        'verbose': str(verbose),
        'kernel_version': kernel_ver,
        'all_versions': str(all_versions)
    }

    if verbose:
        print("Executing: git %s %s" % (subcommand, ' '.join(git_options)))

    send_request(server_url, data, timeout, verbose)


def get_server_url():
    """Return CRASHEXT_SERVER, or None (with an explanation) when unset."""
    try:
        return os.environ['CRASHEXT_SERVER']
    except KeyError:
        print("CRASHEXT_SERVER environment variable not configured")
        print("\nPlease set it to your remote source server URL:")
        print("  export CRASHEXT_SERVER=http://your-server:5000")
        return None


def get_kernel_version():
    """Read the kernel release from the dump, or 'unknown' when unavailable."""
    try:
        sys_output = exec_crash_command("sys")
        for line in sys_output.splitlines():
            words = line.split()
            if len(words) >= 2 and words[0] == "RELEASE:":
                return words[1]
    except Exception as e:
        print("Warning: Could not detect kernel version: %s" % str(e))
    return "unknown"


def send_request(server_url, data, timeout, verbose):
    """POST the request to /api/git and print the server's response."""
    api_url = server_url + '/api/git'

    try:
        if verbose:
            print("Connecting to: %s" % api_url)
            print("Timeout: %d seconds (%d minutes)" % (timeout, timeout // 60))

        encoded_data = urllib.parse.urlencode(data).encode('utf-8')
        req = urllib.request.Request(api_url, data=encoded_data, method='POST')
        response = urllib.request.urlopen(req, timeout=timeout)
        print(response.read().decode('utf-8'))

    except urllib.error.HTTPError as e:
        print("Error: Server returned status code %d" % e.code)
        print(e.read().decode('utf-8'))
    except urllib.error.URLError as e:
        print("\nServer is not reachable.")
        print("Server address is <%s>" % api_url)
        print("\nError: %s" % str(e.reason))
        print("\nMake sure:")
        print("  1. CRASHEXT_SERVER is set correctly")
        print("  2. The remote server is running")
        print("  3. Network connectivity is available")
    except Exception as e:
        print("Unexpected error: %s" % str(e))


def find(args):
    """
    'git find' - look a patch up in the upstream tree by subject or commit ID
    and report whether it was backported into the RHEL tree of this vmcore.
    """
    query_words = []
    mode = 'auto'
    repos = ''
    upstream = ''
    max_count = 10
    timeout = 3600
    use_web = 'auto'
    web_timeout = 20
    message_lines = 20
    check_backport = True
    check_tags = True
    show_patch = False
    show_stat = False
    do_update = False
    verbose = False

    def take_value(arg, index):
        """Return (value, next_index) for '--opt value' or '--opt=value'."""
        if '=' in arg:
            return arg.split('=', 1)[1], index + 1
        if index + 1 < len(args):
            return args[index + 1], index + 2
        return None, index + 1

    i = 0
    while i < len(args):
        arg = args[i]
        name = arg.split('=', 1)[0]

        if arg in ('--help', '-h'):
            print_help_for_subcommand('find')
            return
        elif name in ('--commit', '--subject') and ('=' in arg):
            mode = 'commit' if name == '--commit' else 'subject'
            value, i = take_value(arg, i)
            query_words.append(value)
            continue
        elif arg in ('--commit', '--subject'):
            mode = 'commit' if arg == '--commit' else 'subject'
            i += 1
            continue
        elif name == '--repos':
            repos, i = take_value(arg, i)
            if repos is None:
                print("Error: --repos requires an argument")
                return
            continue
        elif name == '--upstream':
            upstream, i = take_value(arg, i)
            if upstream is None:
                print("Error: --upstream requires an argument")
                return
            continue
        elif name in ('--max-count', '-n'):
            value, i = take_value(arg, i)
            try:
                max_count = int(value)
            except (TypeError, ValueError):
                print("Error: %s requires a number" % name)
                return
            continue
        elif name == '--timeout':
            value, i = take_value(arg, i)
            try:
                timeout = int(value)
            except (TypeError, ValueError):
                print("Error: --timeout requires a number")
                return
            continue
        elif name == '--web-timeout':
            value, i = take_value(arg, i)
            try:
                web_timeout = int(value)
            except (TypeError, ValueError):
                print("Error: --web-timeout requires a number")
                return
            continue
        elif name == '--message-lines':
            value, i = take_value(arg, i)
            try:
                message_lines = int(value)
            except (TypeError, ValueError):
                print("Error: --message-lines requires a number")
                return
            continue
        elif arg == '--no-message':
            message_lines = 0
        elif arg == '--web':
            use_web = 'always'
        elif arg == '--no-web':
            use_web = 'never'
        elif arg == '--no-backport':
            check_backport = False
        elif arg == '--no-tags':
            check_tags = False
        elif arg in ('--patch', '-p'):
            show_patch = True
        elif arg == '--stat':
            show_stat = True
        elif arg == '--update':
            do_update = True
        elif arg == '--verbose':
            verbose = True
        elif arg.startswith('-'):
            print("Error: Unknown option '%s' for 'git find'" % arg)
            print("Try 'git find --help'")
            return
        else:
            # Everything else makes up the subject text
            query_words.append(arg)
        i += 1

    query = ' '.join(w for w in query_words if w)
    if not query:
        print("Error: 'git find' requires a commit ID or subject text")
        print("Try 'git find --help'")
        return

    server_url = get_server_url()
    if server_url is None:
        return

    data = {
        'subcommand': 'find',
        'query': query,
        'mode': mode,
        'repos': repos,
        'upstream': upstream,
        'max_count': str(max_count),
        'check_backport': str(check_backport),
        'check_tags': str(check_tags),
        'show_patch': str(show_patch),
        'show_stat': str(show_stat),
        'update': str(do_update),
        'web': use_web,
        'web_timeout': str(web_timeout),
        'message_lines': str(message_lines),
        'verbose': str(verbose),
        'kernel_version': get_kernel_version(),
        # Leave the server room to finish before the client gives up
        'git_timeout': str(max(10, timeout - 30)),
    }

    if verbose:
        print("Searching for %s: %s" % (mode, query))

    send_request(server_url, data, timeout, verbose)


def print_help():
    print("Usage: git <subcommand> [options]")
    print("")
    print("Subcommands:")
    print("  log        Search git log (supports git log options, default: --max-count=1)")
    print("  show       Show commit details (supports git show options)")
    print("  find       Find an upstream patch by subject or commit ID and report")
    print("             whether it is backported into this kernel")
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
    print("  git find <commit-id> --stat")
    print("  git find mm/slub: fix kmalloc accounting")


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
    elif subcommand == 'find':
        print("Usage: git find <commit-id | subject text> [options]")
        print("")
        print("Look a patch up in the upstream linux tree by commit ID or by")
        print("subject text, then report whether it was backported into the RHEL")
        print("tree matching this vmcore, and whether the running kernel has it.")
        print("")
        print("The query type is detected automatically: 7-40 hex characters are")
        print("treated as a commit ID, anything else as subject text. Subject text")
        print("does not need quoting - all remaining words are joined.")
        print("")
        print("When the local mirrors come up empty, the server also asks the")
        print("public kernel sources (git.kernel.org cgit and the GitHub API for")
        print("torvalds/linux). Any commit found there is still cross-checked for")
        print("backports against the local RHEL trees.")
        print("")
        print("Options:")
        print("  --commit=<id>      Force commit ID lookup")
        print("  --subject=<text>   Force subject text search")
        print("  --max-count=<n>    Maximum matches to report (default: 10)")
        print("  --upstream=<name>  Upstream repo dir name (default: upstream,linux,")
        print("                     mainline,torvalds - first one that exists)")
        print("  --repos=<repos>    Extra repos to check for backports (e.g. rhel8,rhel9)")
        print("  --message-lines=<n> Lines of commit message to show (default: 20)")
        print("  --no-message       Show only the subject, not the message body")
        print("  --web              Always query the public sources, even on a hit")
        print("  --no-web           Never query the public sources (local only)")
        print("  --web-timeout=<s>  Per-request web timeout in seconds (default: 20)")
        print("  --no-backport      Skip the backport cross-check")
        print("  --no-tags          Skip the release-tag lookup (much faster)")
        print("  --patch, -p        Show the full diff of each match")
        print("  --stat             Show a diffstat for each match")
        print("  --update           Fetch the latest branch and tags into every")
        print("                     repo first, reporting each one's before/after")
        print("  --timeout=<secs>   Request timeout in seconds (default: 3600)")
        print("  --verbose          Show verbose output")
        print("")
        print("Examples:")
        print("  git find <commit-id>")
        print("  git find net/mlx5e: Fix crash moving to switchdev mode")
        print("  git find --subject=\"use-after-free in nf_tables\" --max-count=20")
        print("  git find <commit-id> --repos=rhel8,rhel9 --stat")
        print("  git find <commit-id> --web        # ask the public sources too")
        print("  git find <commit-id> --no-web     # local mirrors only")
        print("")
        print("A commit ID that is reported as NOT FOUND exists neither in the")
        print("local trees nor on the public kernel sources - useful for checking")
        print("a suggested or quoted fix.")


if __name__ == '__main__':
    git()
