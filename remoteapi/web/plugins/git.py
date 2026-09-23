"""
remoteapi plugin: /api/git endpoint running git log/show/find in kernel source repositories.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from flask import Flask, request
import email
import email.header
import json
import os
import subprocess
import re
import shlex
import sys
import urllib.error
import urllib.parse
import urllib.request

# Import kernel version utilities from pycrashext source directory
try:
    _src_dir = os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', 'source'))
    if _src_dir not in sys.path:
        sys.path.insert(0, _src_dir)
    from kernel_version import get_rhel_version, parse_kernel_version
except ImportError:
    get_rhel_version = None
    parse_kernel_version = None


# Repository names tried, in order, when looking for the upstream linux tree
UPSTREAM_REPO_NAMES = ('upstream', 'linux', 'mainline', 'torvalds')

# Record/field separators used to parse `git log` output reliably
GIT_REC_SEP = '\x1e'
GIT_FIELD_SEP = '\x1f'
GIT_LOG_FORMAT = ('--format=%H' + GIT_FIELD_SEP + '%an <%ae>' + GIT_FIELD_SEP +
                  '%aI' + GIT_FIELD_SEP + '%s' + GIT_FIELD_SEP + '%b' + GIT_REC_SEP)

COMMIT_ID_RE = re.compile(r'^[0-9a-fA-F]{7,40}$')

# Public sources consulted when the local mirrors come up empty. cgit's
# /patch/?id= endpoint answers with a plain mbox patch, which is both
# authoritative and trivial to parse; the GitHub API is the only one of the
# two that can search commit messages by text.
CGIT_TREES = (
    ('kernel.org/torvalds',
     'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git'),
    ('kernel.org/stable',
     'https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git'),
    ('kernel.org/linux-next',
     'https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git'),
)
GITHUB_API = 'https://api.github.com'
GITHUB_REPO = 'torvalds/linux'
GITHUB_ACCEPT = 'application/vnd.github+json'
WEB_USER_AGENT = 'pycrashext-git-find'
# Enough for the mail headers of even a very wordy commit message; the diff
# that follows is of no interest here.
PATCH_HEADER_BYTES = 64 * 1024


def debug_print(msg):
    """Print debug message only if DEBUG environment variable is set"""
    if os.environ.get('DEBUG', '').lower() in ('1', 'true', 'yes', 'on'):
        print(msg)


def add_plugin_rule(app):
    """Register the git API endpoint"""
    app.add_url_rule('/api/git', 'git', git_command, methods=['POST'])


def colorize_git_output(text):
    """
    Add ANSI color codes to git output (commit messages and diffs).

    Colors:
    - Commit hashes: Yellow
    - Author/Date: Cyan
    - Diff headers (diff --git, +++, ---): Bold white
    - Added lines (+): Green
    - Removed lines (-): Red
    - File paths (@@ ... @@): Magenta
    """
    # ANSI color codes
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    RED = "\033[31m"
    MAGENTA = "\033[35m"
    BOLD_WHITE = "\033[1;37m"
    BLUE = "\033[34m"
    RESET = "\033[0m"

    lines = text.split('\n')
    colored_lines = []

    for line in lines:
        # Commit hash line (starts with "commit ")
        if line.startswith('commit '):
            colored_lines.append(YELLOW + line + RESET)

        # Author and Date lines
        elif line.startswith('Author:') or line.startswith('Date:'):
            colored_lines.append(CYAN + line + RESET)

        # Diff header lines (diff --git, index, ---, +++)
        elif (line.startswith('diff --git') or
              line.startswith('index ') or
              line.startswith('new file mode') or
              line.startswith('deleted file mode')):
            colored_lines.append(BOLD_WHITE + line + RESET)

        # File markers in diff
        elif line.startswith('---') or line.startswith('+++'):
            colored_lines.append(BLUE + line + RESET)

        # Line number markers (@@ ... @@)
        elif line.startswith('@@'):
            colored_lines.append(MAGENTA + line + RESET)

        # Added lines (start with +)
        elif line.startswith('+') and len(line) > 1:
            colored_lines.append(GREEN + line + RESET)

        # Removed lines (start with -)
        elif line.startswith('-') and len(line) > 1:
            colored_lines.append(RED + line + RESET)

        # Regular lines
        else:
            colored_lines.append(line)

    return '\n'.join(colored_lines)


def get_current_rhel_dir(kernel_version='unknown', base_dir=None):
    """
    Determine the current RHEL source directory based on kernel version from vmcore.

    Args:
        kernel_version: Kernel version string from crash dump
        base_dir: Directory holding the repos; defaults to RHEL_SOURCE_DIR

    Returns:
        tuple: (rhel_dir, version_name) e.g., ('/path/to/rhel8', 'rhel8')
                or (None, None) if version cannot be detected
    """
    if base_dir is None:
        try:
            base_dir = os.environ['RHEL_SOURCE_DIR']
        except KeyError:
            return None, None

    # Detect RHEL version from kernel version string
    detected_version = None
    if '.el10' in kernel_version or '.el10_' in kernel_version:
        detected_version = 'rhel10'
    elif '.el9' in kernel_version or '.el9_' in kernel_version:
        detected_version = 'rhel9'
    elif '.el8' in kernel_version or '.el8_' in kernel_version:
        detected_version = 'rhel8'
    elif '.el7' in kernel_version or '.el7_' in kernel_version:
        detected_version = 'rhel7'
    elif '.el6' in kernel_version or '.el6_' in kernel_version:
        detected_version = 'rhel6'
    elif '.el5' in kernel_version or '.el5_' in kernel_version:
        detected_version = 'rhel5'

    # MUST have detected version from kernel - don't fallback to guessing
    if not detected_version:
        return None, None

    # Check if directory exists
    rhel_path = os.path.join(base_dir, detected_version)
    if os.path.isdir(rhel_path):
        return rhel_path, detected_version

    # Directory doesn't exist for detected version
    return None, None


def get_rhel_dirs_ge_version(base_dir, kernel_version):
    """
    Get all rhel source directories with RHEL version >= the version in kernel_version.

    Args:
        base_dir: Base directory containing rhel5, rhel6, ... subdirectories
        kernel_version: Kernel version string from crash dump

    Returns:
        tuple: (repos_list, error_message)
               repos_list is list of (name, path) tuples sorted by version, or None on error
    """
    if get_rhel_version is None:
        return None, "kernel_version utility not available"

    current_rhel_ver = get_rhel_version(kernel_version)
    if current_rhel_ver is None:
        return None, "Could not detect RHEL version from kernel version '%s'" % kernel_version

    repos = []
    try:
        for entry in sorted(os.listdir(base_dir)):
            full_path = os.path.join(base_dir, entry)
            m = re.match(r'^rhel(\d+)$', entry)
            if m and os.path.isdir(full_path):
                dir_rhel_ver = int(m.group(1))
                if dir_rhel_ver >= current_rhel_ver:
                    repos.append((entry, full_path))
    except OSError as e:
        return None, "Cannot list RHEL_SOURCE_DIR: %s" % str(e)

    return repos, None


def get_version_range_for_repo(repo_path, kernel_version):
    """
    Get a git revision range to limit git log to commits where kernel version
    >= kernel_version (i.e. commits in the current version and newer).

    Finds the latest git tag with version strictly less than kernel_version,
    then returns '<that_tag>..' so git log shows commits from that point on.

    Args:
        repo_path: Path to git repository
        kernel_version: Current kernel version string (e.g. "5.14.0-100.el9.x86_64")

    Returns:
        Revision range string like "kernel-5.14.0-99.el9_0.." or None if the
        range cannot be determined (caller should proceed without filtering).
    """
    if parse_kernel_version is None:
        return None

    current_parsed = parse_kernel_version(kernel_version)
    if current_parsed is None:
        return None

    try:
        original_dir = os.getcwd()
        os.chdir(repo_path)

        process = subprocess.Popen(
            ['git', '--no-pager', 'tag', '--list'],
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout_data, _ = process.communicate()
        os.chdir(original_dir)

        if process.returncode != 0:
            return None

        # Parse all tags as kernel versions, stripping common prefixes
        tag_versions = []
        for tag in stdout_data.decode('utf-8').strip().split('\n'):
            tag = tag.strip()
            if not tag:
                continue
            # Validate tag name is safe (no shell injection)
            if not re.match(r'^[\w.\-/]+$', tag):
                continue
            ver_str = tag
            for prefix in ('kernel-', 'v'):
                if tag.startswith(prefix):
                    ver_str = tag[len(prefix):]
                    break
            parsed = parse_kernel_version(ver_str)
            if parsed is not None:
                tag_versions.append((parsed, tag))

        if not tag_versions:
            return None

        # Sort ascending by version tuple
        tag_versions.sort(key=lambda x: x[0])

        # Find the latest tag strictly less than current version
        prev_tag = None
        for parsed, tag in tag_versions:
            if parsed < current_parsed:
                prev_tag = tag
            else:
                break  # list is sorted; first tag >= current means we're done

        if prev_tag is None:
            return None

        # Range: commits after prev_tag includes current version and newer
        return prev_tag + '..'

    except Exception:
        try:
            os.chdir(original_dir)
        except Exception:
            pass
        return None


def git_checkout_latest(repo_path):
    """
    Checkout the latest code in a git repository.

    Args:
        repo_path: Path to git repository

    Returns:
        tuple: (success, message)
    """
    import datetime
    debug_print("[DEBUG %s] git_checkout_latest() STARTED" % datetime.datetime.now().strftime("%H:%M:%S"))
    debug_print("[DEBUG]   repo_path: %s" % repo_path)

    try:
        original_dir = os.getcwd()
        os.chdir(repo_path)
        debug_print("[DEBUG]   Changed to: %s" % os.getcwd())

        # Get the default branch (usually main or master)
        # Use subprocess without shell=True to prevent command injection
        debug_print("[DEBUG]   Getting default branch from remote...")
        branch_process = subprocess.Popen(
            ['git', '--no-pager', 'remote', 'show', 'origin'],
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        remote_output_data, remote_err = branch_process.communicate()
        remote_output = remote_output_data.decode('utf-8')

        # Parse output to find HEAD branch
        default_branch = ''
        for line in remote_output.splitlines():
            if 'HEAD branch' in line:
                default_branch = line.split(':', 1)[1].strip()
                break

        if not default_branch:
            debug_print("[DEBUG]   No HEAD branch found, trying common names...")
            # Fallback to common branch names
            for branch in ['main', 'master', 'trunk']:
                check_process = subprocess.Popen(
                    ['git', '--no-pager', 'rev-parse', '--verify', branch],
                    shell=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                check_out, check_err = check_process.communicate()
                if check_process.returncode == 0:
                    default_branch = branch
                    debug_print("[DEBUG]   Found branch: %s" % branch)
                    break

        if not default_branch:
            default_branch = 'master'  # Ultimate fallback
            debug_print("[DEBUG]   Using ultimate fallback: master")
        else:
            debug_print("[DEBUG]   Default branch: %s" % default_branch)

        # Validate branch name format (alphanumeric, slashes, dashes, underscores)
        if not re.match(r'^[a-zA-Z0-9/_-]+$', default_branch):
            os.chdir(original_dir)
            return False, "Invalid branch name format: %s" % default_branch

        # Fetch latest changes (doesn't require clean working directory)
        fetch_process = subprocess.Popen(
            ['git', '--no-pager', 'fetch', 'origin', default_branch],
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        fetch_out, fetch_err_data = fetch_process.communicate()
        fetch_err = fetch_err_data.decode('utf-8')

        if fetch_process.returncode != 0:
            os.chdir(original_dir)
            return False, "Failed to fetch: %s" % fetch_err

        # Reset to latest (discards any local changes - safe for read-only source repos)
        # Execute checkout
        checkout_process = subprocess.Popen(
            ['git', '--no-pager', 'checkout', '-f', default_branch],
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        checkout_out, checkout_err_data = checkout_process.communicate()
        checkout_err = checkout_err_data.decode('utf-8')

        if checkout_process.returncode != 0:
            os.chdir(original_dir)
            return False, "Failed to checkout: %s" % checkout_err

        # Execute reset
        reset_process = subprocess.Popen(
            ['git', '--no-pager', 'reset', '--hard', 'origin/' + default_branch],
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        reset_out_data, reset_err_data = reset_process.communicate()
        reset_out = reset_out_data.decode('utf-8')
        reset_err = reset_err_data.decode('utf-8')

        os.chdir(original_dir)

        if reset_process.returncode != 0:
            return False, "Failed to reset to latest: %s" % reset_err

        return True, "Successfully updated to latest on branch %s" % default_branch

    except Exception as e:
        try:
            os.chdir(original_dir)
        except:
            pass
        return False, "Exception during checkout: %s" % str(e)


def search_git_log(repo_path, pattern, max_lines=30, max_commits=1, show_context=False):
    """
    Search git log for commits matching a pattern.

    Args:
        repo_path: Path to git repository
        pattern: Search pattern
        max_lines: Maximum lines to show per commit (0 for all)
        max_commits: Maximum commits to search/return (0 for all, capped at 1000)
        show_context: Whether to show file context in patches

    Returns:
        tuple: (success, results_text)
    """
    try:
        original_dir = os.getcwd()
        os.chdir(repo_path)

        # Determine search limit using max_commits directly
        if max_commits == 0:
            search_limit = 1000  # Reasonable limit for "all"
        else:
            search_limit = max_commits

        # Simple git log search with --grep and --max-count
        # Use subprocess with argument list to prevent command injection
        process = subprocess.Popen(
            ['git', '--no-pager', 'log', '--format=%H', '--grep=' + pattern, '--max-count=' + str(search_limit)],
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        process.wait()
        commit_list = process.stdout.read().decode('utf-8').strip()

        if not commit_list:
            os.chdir(original_dir)
            return True, "No matching commits found"

        # Parse commit hashes (one per line)
        commits = []
        for line in commit_list.split('\n'):
            line = line.strip()
            if line:
                commits.append(line)

        # Limit commits if requested
        if max_commits > 0 and len(commits) > max_commits:
            commits = commits[:max_commits]
            truncated = True
        else:
            truncated = False

        # Get detailed info for each commit
        results = []
        for commit in commits:
            # Validate commit hash format (40 hex characters)
            if not re.match(r'^[a-f0-9]{7,40}$', commit):
                continue  # Skip invalid commit hashes

            # Get commit details - use argument list to prevent command injection
            if show_context:
                git_args = ['git', '--no-pager', 'show', commit]
            else:
                git_args = ['git', '--no-pager', 'show', '--stat', commit]

            detail_process = subprocess.Popen(
                git_args,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            detail_process.wait()
            commit_detail = detail_process.stdout.read().decode('utf-8')

            # Limit lines if requested
            if max_lines > 0:
                lines = commit_detail.split('\n')
                if len(lines) > max_lines:
                    commit_detail = '\n'.join(lines[:max_lines])
                    commit_detail += '\n... (output truncated, %d more lines)' % (len(lines) - max_lines)

            # Apply syntax coloring
            colored_detail = colorize_git_output(commit_detail)

            results.append(colored_detail)

        os.chdir(original_dir)

        # Format final output
        BOLD_WHITE = "\033[1;37m"
        RESET = "\033[0m"
        separator = "=" * 80
        output = []

        for i, result in enumerate(results, 1):
            header = "%s\nCommit %d/%d\n%s" % (separator, i, len(results), separator)
            output.append(BOLD_WHITE + header + RESET)
            output.append(result)

        if truncated:
            output.append("\n%s" % separator)
            output.append("Results truncated to %d commits (use --maxmatch=0 for all)" % max_commits)
            output.append(separator)

        return True, '\n'.join(output)

    except Exception as e:
        try:
            os.chdir(original_dir)
        except:
            pass
        return False, "Exception during search: %s" % str(e)


def show_commit(repo_path, commit_id):
    """
    Show full content of a specific commit.

    Args:
        repo_path: Path to git repository
        commit_id: Commit hash or reference

    Returns:
        tuple: (success, commit_content)
    """
    try:
        original_dir = os.getcwd()
        os.chdir(repo_path)

        # Validate commit_id format (alphanumeric, dots, dashes, underscores only)
        if not re.match(r'^[a-zA-Z0-9._-]+$', commit_id):
            os.chdir(original_dir)
            return False, "Error: Invalid commit ID format"

        # Show full commit content - use argument list to prevent command injection
        process = subprocess.Popen(
            ['git', '--no-pager', 'show', commit_id],
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        process.wait()
        commit_content = process.stdout.read().decode('utf-8')
        error_output = process.stderr.read().decode('utf-8')

        os.chdir(original_dir)

        if error_output and ('fatal:' in error_output or 'error:' in error_output):
            return False, "Error: %s" % error_output

        if not commit_content:
            return False, "No content found for commit %s" % commit_id

        # Apply syntax coloring
        colored_content = colorize_git_output(commit_content)

        return True, colored_content

    except Exception as e:
        try:
            os.chdir(original_dir)
        except:
            pass
        return False, "Exception during show commit: %s" % str(e)


def validate_git_option(option):
    """
    Validate a single git option to prevent injection.
    Allows common git options and their values.
    """
    # Allow options that start with - or --
    if option.startswith('-'):
        # Extract the option name (before =)
        opt_name = option.split('=')[0]
        # Common safe git options
        safe_options = [
            '-S', '--grep', '--max-count', '-n', '--stat', '--oneline', '--pretty',
            '--format', '--name-only', '--name-status', '--since', '--until',
            '--author', '--committer', '--all', '--no-merges', '--merges',
            '-p', '-u', '--patch', '--no-patch', '--abbrev-commit',
            '--date', '--graph', '--decorate', '--color', '--no-color'
        ]
        # Check if it's a known safe option or starts with a safe prefix
        for safe_opt in safe_options:
            if opt_name == safe_opt or opt_name.startswith(safe_opt):
                return True
        return False
    else:
        # Non-option arguments (commit refs, paths)
        # Allow alphanumeric, dots, dashes, underscores, tildes, carets, slashes
        return re.match(r'^[a-zA-Z0-9._/~^-]+$', option) is not None


def parse_git_options(git_options_str):
    """
    Parse git options string into safe argument list.
    Returns tuple: (success, args_list_or_error_message)
    """
    if not git_options_str.strip():
        return True, []

    try:
        # Use shlex to properly split options (handles quoted strings)
        args = shlex.split(git_options_str)
    except Exception as e:
        return False, "Error parsing git options: %s" % str(e)

    # Validate each argument
    validated_args = []
    for arg in args:
        if not validate_git_option(arg):
            return False, "Invalid or unsafe git option: %s" % arg
        validated_args.append(arg)

    return True, validated_args


def count_commits(repo_path, git_args):
    """
    Count commits matching the given git log arguments using git rev-list --count.

    Strips display-only options (--oneline, --stat, --format, etc.) that are
    not valid for rev-list, so counting works regardless of output format.

    Args:
        repo_path: Path to git repository
        git_args: List of validated git log arguments

    Returns:
        int: Commit count, or 0 on error
    """
    # Options that control display only — not valid for rev-list
    display_opts = {
        '--oneline', '--stat', '--name-only', '--name-status',
        '--abbrev-commit', '--graph', '--decorate', '--color', '--no-color',
        '-p', '-u', '--patch', '--no-patch',
    }
    # Prefixes of display options that take a value via '='
    display_prefixes = ('--format=', '--pretty=', '--date=', '--color=', '--decorate=')

    import datetime
    debug_print("[DEBUG %s] count_commits() STARTED" % datetime.datetime.now().strftime("%H:%M:%S"))
    debug_print("[DEBUG]   repo_path: %s" % repo_path)
    debug_print("[DEBUG]   git_args: %s" % git_args)

    filtered = []
    for arg in git_args:
        if arg in display_opts:
            continue
        if any(arg.startswith(p) for p in display_prefixes):
            continue
        filtered.append(arg)

    debug_print("[DEBUG]   filtered args (after stripping display opts): %s" % filtered)

    try:
        original_dir = os.getcwd()
        os.chdir(repo_path)
        # Use git log --format=%H instead of git rev-list --count because
        # rev-list does not support -S (pickaxe) or other git-log-only options.
        cmd = ['git', '--no-pager', 'log', '--format=%H'] + filtered
        debug_print("[DEBUG]   Full log command: %s" % ' '.join(cmd))
        process = subprocess.Popen(
            cmd,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout_data, stderr_data = process.communicate()
        os.chdir(original_dir)
        debug_print("[DEBUG]   return code: %s" % process.returncode)
        debug_print("[DEBUG]   stdout: %r" % stdout_data)
        debug_print("[DEBUG]   stderr: %r" % stderr_data)
        if process.returncode == 0:
            lines = [l for l in stdout_data.decode('utf-8').strip().split('\n') if l.strip()]
            result = len(lines)
            debug_print("[DEBUG]   count_commits() returning: %d" % result)
            return result
    except Exception as e:
        debug_print("[DEBUG]   count_commits() EXCEPTION: %s" % str(e))
        try:
            os.chdir(original_dir)
        except Exception:
            pass
    debug_print("[DEBUG]   count_commits() returning: 0 (error/non-zero exit)")
    return 0


def execute_git_command(repo_path, subcommand, git_args):
    """
    Execute a git command in the specified repository.

    Args:
        repo_path: Path to git repository
        subcommand: Git subcommand (log, show)
        git_args: List of validated git arguments

    Returns:
        tuple: (success, output_or_error)
    """
    import datetime
    debug_print("[DEBUG %s] execute_git_command() STARTED" % datetime.datetime.now().strftime("%H:%M:%S"))
    debug_print("[DEBUG]   repo_path: %s" % repo_path)
    debug_print("[DEBUG]   subcommand: %s" % subcommand)
    debug_print("[DEBUG]   git_args: %s" % git_args)

    try:
        original_dir = os.getcwd()
        debug_print("[DEBUG]   original_dir: %s" % original_dir)

        debug_print("[DEBUG]   Changing to repo directory...")
        os.chdir(repo_path)
        debug_print("[DEBUG]   Current directory: %s" % os.getcwd())

        # Add default --max-count=1 for log if not specified
        final_args = list(git_args)
        if subcommand == 'log':
            has_max_count = any(arg.startswith('--max-count') or arg.startswith('-n') for arg in final_args)
            if not has_max_count:
                debug_print("[DEBUG]   Adding default --max-count=1")
                final_args.insert(0, '--max-count=1')
            else:
                debug_print("[DEBUG]   max-count already specified in args")

        # Build git command
        cmd = ['git', '--no-pager', subcommand] + final_args
        debug_print("[DEBUG]   Full command: %s" % ' '.join(cmd))

        # Execute command
        debug_print("[DEBUG]   Executing git command...")
        start_time = datetime.datetime.now()
        process = subprocess.Popen(
            cmd,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        debug_print("[DEBUG]   Waiting for process to complete...")
        # Use communicate() instead of wait() + read() to avoid deadlock
        # communicate() reads output while process is running, preventing buffer overflow
        stdout_data, stderr_data = process.communicate()
        end_time = datetime.datetime.now()
        duration = (end_time - start_time).total_seconds()
        debug_print("[DEBUG]   Process completed in %.2f seconds" % duration)

        output = stdout_data.decode('utf-8')
        error = stderr_data.decode('utf-8')
        debug_print("[DEBUG]   Return code: %d" % process.returncode)
        debug_print("[DEBUG]   Output length: %d chars" % len(output))
        debug_print("[DEBUG]   Error length: %d chars" % len(error))

        os.chdir(original_dir)

        if process.returncode != 0:
            debug_print("[DEBUG]   ERROR: Git command failed with code %d" % process.returncode)
            return False, "Git command failed: %s" % (error or output)

        if not output and error:
            debug_print("[DEBUG]   ERROR: No output but has error")
            return False, "No output: %s" % error

        debug_print("[DEBUG]   Applying syntax coloring...")
        # Apply syntax coloring
        colored_output = colorize_git_output(output)

        debug_print("[DEBUG]   execute_git_command() SUCCESS")
        return True, colored_output

    except Exception as e:
        debug_print("[DEBUG]   EXCEPTION in execute_git_command: %s" % str(e))
        try:
            os.chdir(original_dir)
        except:
            pass
        return False, "Exception executing git command: %s" % str(e)


def run_git(repo_path, args, timeout=300):
    """
    Run a git command inside repo_path without a shell.

    Args:
        repo_path: Repository to run in
        args: List of git arguments (without the leading 'git --no-pager')
        timeout: Seconds to wait before killing the command

    Returns:
        tuple: (returncode, stdout_text, stderr_text). returncode is -1 when
               the command could not be run or timed out.
    """
    process = None
    try:
        process = subprocess.Popen(
            ['git', '--no-pager'] + args,
            cwd=repo_path,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout_data, stderr_data = process.communicate(timeout=timeout)
        return (process.returncode,
                stdout_data.decode('utf-8', 'replace'),
                stderr_data.decode('utf-8', 'replace'))
    except subprocess.TimeoutExpired:
        if process is not None:
            process.kill()
            process.communicate()
        return -1, '', 'git %s timed out after %d seconds' % (args[0] if args else '', timeout)
    except Exception as e:
        return -1, '', str(e)


def parse_log_records(stdout):
    """
    Parse `git log GIT_LOG_FORMAT` output into a list of commit dictionaries.
    """
    commits = []
    for record in stdout.split(GIT_REC_SEP):
        if not record.strip():
            continue
        fields = record.lstrip('\n').split(GIT_FIELD_SEP)
        if len(fields) < 5:
            continue
        commits.append({
            'sha': fields[0].strip(),
            'author': fields[1].strip(),
            'date': fields[2].strip(),
            'subject': fields[3].strip(),
            'body': fields[4],
        })
    return commits


def resolve_repo_path(base_dir, repo_name):
    """
    Turn a repository name into a validated absolute path under base_dir.

    Returns:
        tuple: (path, error_message). path is None when the name is rejected.
    """
    if not repo_name:
        return None, "Empty repository name"
    if '..' in repo_name or '/' in repo_name or '\\' in repo_name or repo_name.startswith('/'):
        return None, "Invalid repository name '%s' - path traversal not allowed" % repo_name

    repo_path = os.path.normpath(os.path.join(base_dir, repo_name))
    if not repo_path.startswith(os.path.normpath(base_dir) + os.sep):
        return None, "Path traversal detected in repository name '%s'" % repo_name
    if not os.path.isdir(repo_path):
        return None, "Repository directory not found: %s" % repo_path
    return repo_path, None


def is_git_repo(path):
    """Return True when path is inside/at a git repository."""
    rc, _out, _err = run_git(path, ['rev-parse', '--git-dir'], timeout=30)
    return rc == 0


def find_upstream_repo(base_dir, preferred=''):
    """
    Locate the upstream linux repository under base_dir.

    Directories that exist but are not git repositories are skipped, so an
    extracted source tree sitting next to the real clones cannot shadow it.

    Args:
        base_dir: RHEL_SOURCE_DIR
        preferred: Comma separated repo names to try first (from --upstream)

    Returns:
        tuple: (repo_name, repo_path, skipped) where skipped lists names that
               exist but are not git repositories. (None, None, skipped) when
               nothing usable matches.
    """
    candidates = [n.strip() for n in preferred.split(',') if n.strip()]
    if not candidates:
        candidates = list(UPSTREAM_REPO_NAMES)

    skipped = []
    for name in candidates:
        repo_path, _err = resolve_repo_path(base_dir, name)
        if repo_path is None:
            continue
        if not is_git_repo(repo_path):
            skipped.append(name)
            continue
        return name, repo_path, skipped
    return None, None, skipped


def strip_tag_prefix(tag):
    """Strip the 'kernel-' or leading 'v' prefix used by kernel release tags."""
    for prefix in ('kernel-', 'v'):
        if tag.startswith(prefix):
            return tag[len(prefix):]
    return tag


def parse_upstream_tag(tag):
    """
    Parse an upstream kernel tag (v6.9, v6.9.3, v6.10-rc2) into a sort key.

    Returns:
        tuple (major, minor, patch, is_final, rc) or None when unparsable.
        Release candidates sort before the matching final release.
    """
    m = re.match(r'^v?(\d+)\.(\d+)(?:\.(\d+))?(?:-rc(\d+))?$', tag.strip())
    if not m:
        return None
    major, minor, patch, rc = m.groups()
    if rc is None:
        return (int(major), int(minor), int(patch or 0), 1, 0)
    return (int(major), int(minor), int(patch or 0), 0, int(rc))


def earliest_release_tag(repo_path, sha, timeout=300):
    """
    Find the earliest release tag that contains the given commit.

    RHEL style tags (kernel-5.14.0-427.el9) are preferred when present;
    otherwise upstream style tags (v6.9-rc1) are used.

    Returns:
        tuple: (tag_name, sort_key, kind) where kind is 'rhel' or 'upstream',
               or (None, None, None) when no release tag contains the commit.
    """
    rc, out, _err = run_git(repo_path, ['tag', '--contains', sha], timeout=timeout)
    if rc != 0:
        return None, None, None

    rhel_tags = []
    upstream_tags = []
    for tag in out.split('\n'):
        tag = tag.strip()
        if not tag or not re.match(r'^[\w.\-/]+$', tag):
            continue
        base = strip_tag_prefix(tag)
        if parse_kernel_version is not None:
            key = parse_kernel_version(base)
            if key is not None:
                rhel_tags.append((key, tag))
                continue
        key = parse_upstream_tag(tag)
        if key is not None:
            upstream_tags.append((key, tag))

    if rhel_tags:
        key, tag = min(rhel_tags)
        return tag, key, 'rhel'
    if upstream_tags:
        key, tag = min(upstream_tags)
        return tag, key, 'upstream'
    return None, None, None


def find_backport(repo_path, upstream_sha, subject, timeout=300):
    """
    Look for a commit in repo_path that corresponds to an upstream commit.

    Two strategies are tried, strongest first:
      1. The upstream commit ID quoted in the commit message. RHEL backports
         carry "commit <sha> upstream." or "(cherry picked from commit <sha>)".
      2. An identical (or contained) subject line.

    Returns:
        tuple: (commit_dict, match_method) or (None, None) when not found.
    """
    if upstream_sha and len(upstream_sha) >= 12:
        rc, out, _err = run_git(
            repo_path,
            ['log', '--all', '--max-count=5', '--fixed-strings',
             '--grep=' + upstream_sha[:12], GIT_LOG_FORMAT],
            timeout=timeout)
        if rc == 0:
            commits = parse_log_records(out)
            if commits:
                return commits[0], 'upstream commit ID referenced in commit message'

    if subject:
        rc, out, _err = run_git(
            repo_path,
            ['log', '--all', '--max-count=10', '--fixed-strings',
             '--grep=' + subject, GIT_LOG_FORMAT],
            timeout=timeout)
        if rc == 0:
            commits = parse_log_records(out)
            for commit in commits:
                if commit['subject'] == subject:
                    return commit, 'identical subject line'
            if commits:
                return commits[0], 'subject text found in commit message'

    return None, None


def lookup_commit(repo_path, commit_id, timeout=300):
    """
    Fetch a single commit by ID. Returns the commit dict, or None when the
    ID does not resolve to a commit in this repository.
    """
    if not COMMIT_ID_RE.match(commit_id):
        return None
    rc, out, _err = run_git(
        repo_path,
        ['log', '--max-count=1', GIT_LOG_FORMAT, commit_id, '--'],
        timeout=timeout)
    if rc != 0:
        return None
    commits = parse_log_records(out)
    return commits[0] if commits else None


def search_commits(repo_path, text, max_count, search_all_refs=True, timeout=600):
    """
    Search commit messages for a literal text (typically a patch subject).
    """
    args = ['log', '--max-count=%d' % max_count, '--fixed-strings',
            '--regexp-ignore-case', '--grep=' + text]
    if search_all_refs:
        args.append('--all')
    args.append(GIT_LOG_FORMAT)
    rc, out, _err = run_git(repo_path, args, timeout=timeout)
    if rc != 0:
        return []
    return parse_log_records(out)


def describe_presence(repo_path, sha, kernel_version, check_tags, timeout, indent):
    """
    Describe when a commit first appeared in a release, and whether that
    release is at or below the kernel version taken from the vmcore.

    Returns a list of description lines prefixed with the given indent.
    """
    if not check_tags:
        return []

    tag, key, kind = earliest_release_tag(repo_path, sha, timeout=timeout)
    if tag is None:
        return [indent + "first release  : none (not in any tagged release yet)"]

    lines = [indent + "first release  : %s" % tag]
    if kind == 'rhel' and parse_kernel_version is not None:
        current = parse_kernel_version(kernel_version)
        if current is not None:
            if current >= key:
                lines.append(indent + "running kernel : PRESENT (%s >= %s)" %
                             (kernel_version, tag))
            else:
                lines.append(indent + "running kernel : NOT PRESENT "
                             "(%s is older than %s)" % (kernel_version, tag))
    return lines


def web_is_disabled():
    """True when the administrator turned web lookups off server-side."""
    return os.environ.get('PYCRASHEXT_NO_WEB', '').lower() in ('1', 'true', 'yes', 'on')


def http_get(url, timeout, accept=None, max_bytes=0):
    """
    Fetch a URL. Proxies are taken from the usual http_proxy/https_proxy
    environment variables.

    max_bytes caps how much of the body is read (0 means no cap). A tree-wide
    patch can run to hundreds of megabytes and we only ever need the mail
    headers at the top of it.

    Returns:
        tuple: (body_text, error). error is None on success, 'HTTP 404' when
               the resource simply is not there, an error string otherwise.
    """
    headers = {'User-Agent': WEB_USER_AGENT}
    if accept:
        headers['Accept'] = accept
    token = os.environ.get('GITHUB_TOKEN', '')
    if token and url.startswith(GITHUB_API):
        headers['Authorization'] = 'Bearer ' + token

    try:
        req = urllib.request.Request(url, headers=headers)
        response = urllib.request.urlopen(req, timeout=timeout)
        try:
            raw = response.read(max_bytes) if max_bytes > 0 else response.read()
            return raw.decode('utf-8', 'replace'), None
        finally:
            response.close()
    except urllib.error.HTTPError as e:
        if e.code == 403:
            return None, 'HTTP 403 (rate limited? set GITHUB_TOKEN to raise the limit)'
        return None, 'HTTP %d' % e.code
    except urllib.error.URLError as e:
        return None, str(e.reason)
    except Exception as e:
        return None, str(e)


def parse_mbox_patch(text):
    """
    Parse a cgit /patch/ response (an mbox formatted patch) into a commit
    dictionary. Returns None when the body is not a patch, which is how cgit
    answers for an unknown commit ID.
    """
    if not text or not text.startswith('From '):
        return None
    m = re.match(r'^From ([0-9a-f]{7,40})', text)
    if not m:
        return None
    sha = m.group(1)

    if '\n' not in text:
        return None
    try:
        msg = email.message_from_string(text.split('\n', 1)[1])
    except Exception:
        return None

    def header(name):
        raw = msg.get(name, '')
        try:
            return str(email.header.make_header(email.header.decode_header(raw)))
        except Exception:
            return raw

    # cgit formats the subject as a patch mail, so drop the [PATCH] prefix
    subject = re.sub(r'^\[[^\]]*PATCH[^\]]*\]\s*', '', header('Subject')).strip()
    if not subject:
        return None

    return {'sha': sha, 'author': header('From'), 'date': header('Date'),
            'subject': subject, 'body': ''}


def github_commit_dict(data):
    """Turn a GitHub commit API object into our commit dictionary."""
    commit = data.get('commit') or {}
    author = commit.get('author') or {}
    message = commit.get('message') or ''
    name = author.get('name') or ''
    mail = author.get('email') or ''
    return {
        'sha': data.get('sha') or '',
        'author': ('%s <%s>' % (name, mail)).strip(),
        'date': author.get('date') or '',
        'subject': message.split('\n', 1)[0].strip(),
        'body': message,
        'url': data.get('html_url') or '',
    }


def github_commit(sha, timeout):
    """Look a commit up by ID through the GitHub API."""
    url = '%s/repos/%s/commits/%s' % (GITHUB_API, GITHUB_REPO,
                                      urllib.parse.quote(sha, safe=''))
    body, err = http_get(url, timeout, accept=GITHUB_ACCEPT)
    if body is None:
        return None, err
    try:
        data = json.loads(body)
    except ValueError as e:
        return None, 'unreadable response (%s)' % e
    commit = github_commit_dict(data)
    return (commit, None) if commit['sha'] else (None, 'HTTP 404')


def github_search(text, max_count, timeout):
    """Search commit messages through the GitHub commit search API."""
    query = '%s repo:%s' % (text, GITHUB_REPO)
    url = '%s/search/commits?q=%s&per_page=%d' % (
        GITHUB_API, urllib.parse.quote(query, safe=''), min(max(max_count, 1), 100))
    body, err = http_get(url, timeout, accept=GITHUB_ACCEPT)
    if body is None:
        return None, err
    try:
        data = json.loads(body)
    except ValueError as e:
        return None, 'unreadable response (%s)' % e
    items = data.get('items') or []
    return [github_commit_dict(i) for i in items[:max_count]], None


def web_find(query, mode, max_count, timeout):
    """
    Look a patch up on the public kernel sources.

    Returns:
        tuple: (matches, notes) where matches is a list of (source, commit)
               and notes carries per-source problems worth showing. A plain
               'not here' answer is not a note.
    """
    matches = []
    notes = []

    def note(source, err):
        # 404, and GitHub's 422 for an unknown sha, just mean "not in this tree"
        if err and err not in ('HTTP 404', 'HTTP 422'):
            notes.append('%s: %s' % (source, err))

    if mode == 'commit':
        for name, base in CGIT_TREES:
            url = '%s/patch/?id=%s' % (base, urllib.parse.quote(query, safe=''))
            body, err = http_get(url, timeout, max_bytes=PATCH_HEADER_BYTES)
            if body is None:
                note(name, err)
                continue
            commit = parse_mbox_patch(body)
            # cgit answers an unresolvable id with HEAD rather than a 404, so
            # never trust a patch whose sha is not the one we asked for.
            if commit is not None and commit['sha'].startswith(query.lower()):
                commit['url'] = '%s/commit/?id=%s' % (base, commit['sha'])
                matches.append((name, commit))
                return matches, notes

        commit, err = github_commit(query, timeout)
        if commit is not None and commit['sha'].startswith(query.lower()):
            matches.append(('github/' + GITHUB_REPO, commit))
        else:
            note('github', err)
    else:
        commits, err = github_search(query, max_count, timeout)
        if commits:
            for commit in commits:
                matches.append(('github/' + GITHUB_REPO, commit))
        else:
            note('github', err)

    return matches, notes


def format_commit_block(index, total, commit, label, colors):
    """Format the header block describing one matched commit."""
    YELLOW, CYAN, BOLD_WHITE, RESET = colors
    lines = []
    lines.append(YELLOW + "[%d/%d] %s  (%s)" % (index, total, commit['sha'], label) + RESET)
    lines.append("    subject : " + BOLD_WHITE + commit['subject'] + RESET)
    lines.append("    author  : %s" % commit['author'])
    lines.append("    date    : %s" % commit['date'])
    return lines


def find_command(query, mode, kernel_version, base_dir, upstream_pref, extra_repos,
                 max_count, check_backport, check_tags, show_patch, show_stat,
                 do_update, verbose, timeout, use_web='auto', web_timeout=20):
    """
    Handle the 'find' subcommand: look a patch up in the upstream tree by
    subject or commit ID, then report whether it was backported into the
    RHEL tree matching the vmcore.

    use_web selects when the public kernel sources are consulted: 'auto' only
    when the local mirrors come up empty, 'always' on every search, 'never'.
    """
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    RED = "\033[31m"
    BOLD_WHITE = "\033[1;37m"
    RESET = "\033[0m"
    colors = (YELLOW, CYAN, BOLD_WHITE, RESET)
    separator = "=" * 80

    out = []

    upstream_name, upstream_path, skipped = find_upstream_repo(base_dir, upstream_pref)
    if upstream_path is None:
        tried = upstream_pref if upstream_pref else ', '.join(UPSTREAM_REPO_NAMES)
        msg = ["Error: No upstream git repository found under %s" % base_dir,
               "Tried: %s" % tried]
        if skipped:
            msg.append("These exist but are not git repositories: %s" %
                       ', '.join(skipped))
        msg.append("Clone the upstream linux tree there, or pass --upstream=<dirname>.")
        return '\n'.join(msg)

    # RHEL repositories to cross-check for backports
    backport_repos = []
    rhel_path, rhel_name = get_current_rhel_dir(kernel_version, base_dir)
    if rhel_path is not None and is_git_repo(rhel_path):
        backport_repos.append((rhel_name, os.path.normpath(rhel_path)))
    for name in [r.strip() for r in extra_repos.split(',') if r.strip()]:
        repo_path, err = resolve_repo_path(base_dir, name)
        if repo_path is None:
            return "Error: %s" % err
        if not is_git_repo(repo_path):
            return "Error: '%s' is not a git repository (%s)" % (name, repo_path)
        if repo_path not in [p for _n, p in backport_repos]:
            backport_repos.append((name, repo_path))

    if do_update:
        for name, path in [(upstream_name, upstream_path)] + backport_repos:
            ok, msg = git_checkout_latest(path)
            if verbose or not ok:
                out.append(CYAN + "[update %s] %s" % (name, msg) + RESET)

    # Auto-detect what kind of query this is
    if mode == 'auto':
        mode = 'commit' if COMMIT_ID_RE.match(query) else 'subject'

    out.append(BOLD_WHITE + separator + RESET)
    out.append(BOLD_WHITE + "Git Find Results" + RESET)
    out.append(CYAN + "Query          : %s" % query + RESET)
    out.append(CYAN + "Match mode     : %s" % mode + RESET)
    out.append(CYAN + "Kernel version : %s" % kernel_version + RESET)
    out.append(CYAN + "Upstream repo  : %s%s" %
               (upstream_name, " (%s)" % upstream_path if verbose else "") + RESET)
    if backport_repos:
        out.append(CYAN + "Backport check : %s" %
                   ', '.join(n for n, _p in backport_repos) + RESET)
    out.append(CYAN + "Web lookup     : %s" %
               ("off (PYCRASHEXT_NO_WEB)" if web_is_disabled() else
                {'always': 'always', 'never': 'off'}.get(use_web,
                                                         'on local miss')) + RESET)
    out.append(BOLD_WHITE + separator + RESET)
    out.append("")

    # Collect matches, remembering which repository each came from
    matches = []
    if mode == 'commit':
        commit = lookup_commit(upstream_path, query, timeout=timeout)
        if commit is not None:
            matches.append((upstream_name, upstream_path, commit))
        else:
            # The ID may be a RHEL commit rather than an upstream one
            for name, path in backport_repos:
                commit = lookup_commit(path, query, timeout=timeout)
                if commit is not None:
                    matches.append((name, path, commit))
                    break
    else:
        for commit in search_commits(upstream_path, query, max_count, timeout=timeout):
            matches.append((upstream_name, upstream_path, commit))
        if not matches:
            # Fall back to the RHEL trees: the patch may be RHEL-only
            for name, path in backport_repos:
                found = search_commits(path, query, max_count, timeout=timeout)
                for commit in found:
                    matches.append((name, path, commit))
                if found:
                    break

    # The local mirrors can be stale, or the patch may be too new / in a tree
    # nobody cloned here. Ask the public sources before giving up.
    web_matches = []
    web_notes = []
    if use_web == 'always' or (use_web == 'auto' and not matches):
        if web_is_disabled():
            web_notes.append('web lookup is disabled on the server (PYCRASHEXT_NO_WEB)')
        else:
            web_matches, web_notes = web_find(query, mode, max_count, web_timeout)

    if not matches and not web_matches:
        out.append(RED + "NOT FOUND: no commit matches this %s." %
                   ("commit ID" if mode == 'commit' else "subject text") + RESET)
        out.append("")
        if mode == 'commit':
            out.append("  The commit ID does not exist in '%s'%s." %
                       (upstream_name,
                        " or " + ', '.join(n for n, _p in backport_repos)
                        if backport_repos else ""))
            if use_web != 'never' and not web_is_disabled():
                out.append("  It is not on the public kernel sources either.")
            out.append("  A suggested commit ID that cannot be found here is very")
            out.append("  likely wrong - double check it before relying on it.")
        else:
            out.append("  No commit message contains this text.")
            out.append("  Try a shorter or more distinctive part of the subject line.")
        out.append("")
        if not do_update:
            out.append("  The local mirror may also be out of date - rerun with")
            out.append("  --update to fetch the latest before searching.")
        out.append("")
        out.append("  Searched:")
        for name, path in [(upstream_name, upstream_path)] + backport_repos:
            rc, head, _err = run_git(path, ['log', '--max-count=1', '--format=%H %cI'],
                                     timeout=60)
            state = head.strip() if rc == 0 and head.strip() else "unreadable"
            out.append("    %-10s %s" % (name, path))
            out.append("    %-10s HEAD %s" % ("", state))
        if use_web != 'never' and not web_is_disabled():
            if mode == 'commit':
                for name, _base in CGIT_TREES:
                    out.append("    %-10s %s" % (name, '(web)'))
            out.append("    %-10s %s" % ('github', GITHUB_REPO + ' (web)'))
        for note in web_notes:
            out.append("  " + YELLOW + "web: %s" % note + RESET)
        out.append(BOLD_WHITE + separator + RESET)
        return '\n'.join(out)

    for idx, (repo_name, repo_path, commit) in enumerate(matches, 1):
        out.extend(format_commit_block(idx, len(matches), commit, repo_name, colors))
        out.extend(describe_presence(repo_path, commit['sha'], kernel_version,
                                     check_tags, timeout, "    "))

        if check_backport and repo_path == upstream_path:
            for name, path in backport_repos:
                backport, method = find_backport(path, commit['sha'],
                                                 commit['subject'], timeout=timeout)
                if backport is None:
                    out.append("    %s : " % name + RED + "NOT BACKPORTED" + RESET +
                               " (no matching commit found)")
                    continue
                out.append("    %s : " % name + GREEN + "BACKPORTED" + RESET +
                           " as %s" % backport['sha'])
                out.append("        matched by     : %s" % method)
                out.extend(describe_presence(path, backport['sha'], kernel_version,
                                             check_tags, timeout, "        "))

        if show_patch or show_stat:
            args = ['show', '--stat' if show_stat and not show_patch else '--patch',
                    commit['sha']]
            rc, detail, err = run_git(repo_path, args, timeout=timeout)
            out.append("")
            out.append(colorize_git_output(detail) if rc == 0 else "Error: %s" % err)

        out.append("")

    if web_matches:
        out.append(BOLD_WHITE + "Found on public kernel sources" + RESET)
        if not matches:
            out.append(YELLOW + "The local mirror does not have this commit - it may be "
                       "newer than\nthe last fetch, or live in a tree that is not "
                       "cloned here." + RESET)
        out.append("")

        for idx, (source, commit) in enumerate(web_matches, 1):
            out.extend(format_commit_block(idx, len(web_matches), commit, source, colors))
            if commit.get('url'):
                out.append("    url     : %s" % commit['url'])

            # We know the sha and subject now, so the local backport check can
            # still answer the question that actually matters.
            if check_backport:
                for name, path in backport_repos:
                    backport, method = find_backport(path, commit['sha'],
                                                     commit['subject'], timeout=timeout)
                    if backport is None:
                        out.append("    %s : " % name + RED + "NOT BACKPORTED" + RESET +
                                   " (no matching commit found)")
                        continue
                    out.append("    %s : " % name + GREEN + "BACKPORTED" + RESET +
                               " as %s" % backport['sha'])
                    out.append("        matched by     : %s" % method)
                    out.extend(describe_presence(path, backport['sha'], kernel_version,
                                                 check_tags, timeout, "        "))
            out.append("")

    for note in web_notes:
        out.append(YELLOW + "web: %s" % note + RESET)
    if web_notes:
        out.append("")

    total = len(matches) + len(web_matches)
    out.append(BOLD_WHITE + separator + RESET)
    out.append(BOLD_WHITE + "Complete - %d match%s" %
               (total, "es" if total != 1 else "") + RESET)
    out.append(BOLD_WHITE + separator + RESET)
    return '\n'.join(out)


def git_command():
    """
    Main git endpoint handler.

    Executes git log/show/find commands in kernel source repositories.
    """
    import datetime
    debug_print("\n" + "="*80)
    debug_print("[DEBUG %s] git_command() - REQUEST RECEIVED" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    debug_print("="*80)

    # Get parameters from request
    try:
        subcommand = request.form.get('subcommand', '')
        git_options_str = request.form.get('git_options', '')
        repos_str = request.form.get('repos', '')
        verbose = request.form.get('verbose', 'False') == 'True'
        kernel_version = request.form.get('kernel_version', 'unknown')
        all_versions = request.form.get('all_versions', 'False') == 'True'

        debug_print("[DEBUG] Request parameters:")
        print("  - subcommand: %s" % subcommand)
        print("  - git_options_str: %s" % git_options_str)
        print("  - repos_str: %s" % repos_str)
        print("  - verbose: %s" % verbose)
        print("  - kernel_version: %s" % kernel_version)
        print("  - all_versions: %s" % all_versions)
    except Exception as e:
        debug_print("[DEBUG] ERROR parsing request parameters: %s" % str(e))
        return "Error parsing request parameters: %s" % str(e)

    # Validate subcommand
    if subcommand not in ['log', 'show', 'find']:
        debug_print("[DEBUG] ERROR: Invalid subcommand '%s'" % subcommand)
        return "Error: Invalid subcommand '%s'. Must be 'log', 'show' or 'find'." % subcommand

    if subcommand == 'find':
        try:
            base_dir = os.environ['RHEL_SOURCE_DIR']
        except KeyError:
            return "Error: RHEL_SOURCE_DIR environment variable not set"

        query = request.form.get('query', '').strip()
        if not query:
            return "Error: 'find' requires a commit ID or subject text"

        try:
            max_count = max(1, min(int(request.form.get('max_count', '10')), 200))
        except ValueError:
            max_count = 10
        try:
            git_timeout = max(10, min(int(request.form.get('git_timeout', '600')), 3600))
        except ValueError:
            git_timeout = 600
        try:
            web_timeout = max(5, min(int(request.form.get('web_timeout', '20')), 300))
        except ValueError:
            web_timeout = 20

        mode = request.form.get('mode', 'auto')
        if mode not in ('auto', 'commit', 'subject'):
            mode = 'auto'

        use_web = request.form.get('web', 'auto')
        if use_web not in ('auto', 'always', 'never'):
            use_web = 'auto'

        return find_command(
            query=query,
            mode=mode,
            kernel_version=kernel_version,
            base_dir=base_dir,
            upstream_pref=request.form.get('upstream', ''),
            extra_repos=repos_str,
            max_count=max_count,
            check_backport=request.form.get('check_backport', 'True') == 'True',
            check_tags=request.form.get('check_tags', 'True') == 'True',
            show_patch=request.form.get('show_patch', 'False') == 'True',
            show_stat=request.form.get('show_stat', 'False') == 'True',
            do_update=request.form.get('update', 'False') == 'True',
            verbose=verbose,
            timeout=git_timeout,
            use_web=use_web,
            web_timeout=web_timeout)

    debug_print("[DEBUG] Parsing git options...")
    # Parse and validate git options
    success, result = parse_git_options(git_options_str)
    if not success:
        debug_print("[DEBUG] ERROR parsing git options: %s" % result)
        return result  # Error message
    git_args = result
    debug_print("[DEBUG] Parsed git_args: %s" % git_args)

    # Color constants
    BOLD_WHITE = "\033[1;37m"
    CYAN = "\033[36m"
    YELLOW = "\033[33m"
    RESET = "\033[0m"

    results = []
    separator = "=" * 80

    # Determine which repositories to search
    repos_to_search = []

    debug_print("[DEBUG] Getting base directory from RHEL_SOURCE_DIR...")
    # Get base directory
    try:
        base_dir = os.environ['RHEL_SOURCE_DIR']
        debug_print("[DEBUG] RHEL_SOURCE_DIR: %s" % base_dir)
    except KeyError:
        debug_print("[DEBUG] ERROR: RHEL_SOURCE_DIR not set")
        return "Error: RHEL_SOURCE_DIR environment variable not set"

    # Determine which repos to include based on subcommand and repos_str
    debug_print("[DEBUG] Getting current RHEL repo for kernel version: %s" % kernel_version)
    rhel_path, rhel_name = get_current_rhel_dir(kernel_version)
    if rhel_path is None:
        debug_print("[DEBUG] ERROR: Could not detect RHEL version from kernel version '%s'" % kernel_version)
        return "Error: Could not detect RHEL version from kernel version '%s'\n" \
               "Kernel version must contain .el5, .el6, .el7, .el8, .el9, or .el10\n" \
               "Or RHEL_SOURCE_DIR not set" % kernel_version

    # For 'show' with explicit repos: use ONLY the specified repos (skip current).
    # For 'show' without repos: use current repo only.
    # For 'log': always include current repo (with version filter), plus any extra repos.
    if subcommand == 'show' and repos_str:
        debug_print("[DEBUG] show + repos_str: skipping current repo, using only specified repos")
    else:
        # Current repo: apply version filter for 'log' unless --all is set; no filter for 'show'
        apply_filter = (subcommand == 'log') and (not all_versions)
        repos_to_search.append((rhel_name, rhel_path, apply_filter))
        debug_print("[DEBUG] Added current repo: %s -> %s (version_filter=%s)" % (rhel_name, rhel_path, apply_filter))

    if repos_str:
        debug_print("[DEBUG] User specified repos: %s" % repos_str)
        repo_names = [r.strip() for r in repos_str.split(',')]

        for repo_name in repo_names:
            debug_print("[DEBUG] Processing repo: %s" % repo_name)
            # Validate repo name to prevent path traversal
            if '..' in repo_name or repo_name.startswith('/') or '/' in repo_name or '\\' in repo_name:
                return "Error: Invalid repository name '%s' - path traversal not allowed" % repo_name

            repo_path = os.path.join(base_dir, repo_name)

            # Normalize and verify path
            repo_path = os.path.normpath(repo_path)
            base_dir_normalized = os.path.normpath(base_dir)
            if not repo_path.startswith(base_dir_normalized + os.sep):
                return "Error: Path traversal detected in repository name '%s'" % repo_name

            if not os.path.isdir(repo_path):
                return "Error: Repository directory not found: %s" % repo_path

            # Specified repos: never apply version filter
            repos_to_search.append((repo_name, repo_path, False))
            debug_print("[DEBUG] Added repo to search list: %s -> %s (version_filter=False)" % (repo_name, repo_path))

    # Add header
    results.append(BOLD_WHITE + separator + RESET)
    results.append(BOLD_WHITE + "Git %s Results" % subcommand.title() + RESET)
    results.append(CYAN + "Command: git %s %s" % (subcommand, ' '.join(git_args)) + RESET)
    results.append(CYAN + "Kernel version: %s" % kernel_version + RESET)
    if subcommand == 'show':
        if repos_str:
            results.append(CYAN + "Mode: Searching specified repos only: %s" % repos_str + RESET)
        else:
            results.append(CYAN + "Mode: Searching current repo (%s) only" % rhel_name + RESET)
    else:
        if all_versions:
            results.append(CYAN + "Mode: All commits (version filter disabled)" + RESET)
        else:
            results.append(CYAN + "Mode: Commits >= current kernel version for current repo (use --all to show all versions)" + RESET)
        if repos_str:
            results.append(CYAN + "Additional repos (fully searched): %s" % repos_str + RESET)
    results.append(BOLD_WHITE + separator + RESET)
    results.append("")

    # Execute git command in each repository
    commit_counts = {}
    debug_print("[DEBUG] Total repositories to search: %d" % len(repos_to_search))
    for idx, (repo_name, repo_path, apply_version_filter) in enumerate(repos_to_search, 1):
        debug_print("[DEBUG] Processing repository %d/%d: %s" % (idx, len(repos_to_search), repo_name))
        debug_print("[DEBUG] Repository path: %s" % repo_path)
        results.append(YELLOW + "[Repository: %s]" % repo_name + RESET)

        if verbose:
            results.append("Checking out latest code...")

        debug_print("[DEBUG] Calling git_checkout_latest()...")
        success, msg = git_checkout_latest(repo_path)
        debug_print("[DEBUG] git_checkout_latest() returned: success=%s" % success)
        if not success:
            debug_print("[DEBUG] Checkout warning: %s" % msg)
            results.append("Warning: %s" % msg)
        elif verbose:
            results.append(msg)

        if verbose:
            results.append("Executing: git %s %s" % (subcommand, ' '.join(git_args)))

        debug_print("[DEBUG] Calling execute_git_command()...")
        # Apply version range filter for git log based on per-repo flag
        repo_git_args = list(git_args)
        if subcommand == 'log' and apply_version_filter:
            version_range = get_version_range_for_repo(repo_path, kernel_version)
            if version_range:
                repo_git_args.append(version_range)
                debug_print("[DEBUG] Applied version range filter: %s" % version_range)
            else:
                debug_print("[DEBUG] No version range filter available for this repo")
        debug_print("[DEBUG] Command: git %s %s" % (subcommand, ' '.join(repo_git_args)))
        # Execute git command
        success, output = execute_git_command(repo_path, subcommand, repo_git_args)
        debug_print("[DEBUG] execute_git_command() returned: success=%s" % success)
        if success:
            debug_print("[DEBUG] Output length: %d chars" % len(output))
            results.append(output)
            if subcommand == 'log':
                commit_counts[repo_name] = count_commits(repo_path, repo_git_args)
        else:
            debug_print("[DEBUG] Error: %s" % output)
            results.append("Error: %s" % output)

        results.append("")

    debug_print("[DEBUG] All repositories processed. Preparing response...")

    # Add footer
    results.append(BOLD_WHITE + separator + RESET)
    results.append(BOLD_WHITE + "Complete" + RESET)

    if subcommand == 'log' and commit_counts:
        results.append("")
        results.append(BOLD_WHITE + "Commit counts:" + RESET)
        for repo_name, count in commit_counts.items():
            results.append(CYAN + "  %s: %d commit%s" % (repo_name, count, "s" if count != 1 else "") + RESET)

    results.append(BOLD_WHITE + separator + RESET)

    response = '\n'.join(results)
    debug_print("[DEBUG] Response prepared, length: %d chars" % len(response))
    debug_print("[DEBUG] git_command() COMPLETE - Returning response")
    debug_print("="*80 + "\n")
    return response
