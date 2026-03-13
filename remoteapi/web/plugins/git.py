"""
Written by Daniel Sungju Kwon

Server-side plugin for executing git log/show commands in kernel source repositories
"""

from flask import Flask, request
import os
import subprocess
import re
import shlex


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


def get_current_rhel_dir(kernel_version='unknown'):
    """
    Determine the current RHEL source directory based on kernel version from vmcore.

    Args:
        kernel_version: Kernel version string from crash dump

    Returns:
        tuple: (rhel_dir, version_name) e.g., ('/path/to/rhel8', 'rhel8')
                or (None, None) if version cannot be detected
    """
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


def git_command():
    """
    Main git endpoint handler.

    Executes git log/show commands in kernel source repositories.
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

        debug_print("[DEBUG] Request parameters:")
        print("  - subcommand: %s" % subcommand)
        print("  - git_options_str: %s" % git_options_str)
        print("  - repos_str: %s" % repos_str)
        print("  - verbose: %s" % verbose)
        print("  - kernel_version: %s" % kernel_version)
    except Exception as e:
        debug_print("[DEBUG] ERROR parsing request parameters: %s" % str(e))
        return "Error parsing request parameters: %s" % str(e)

    # Validate subcommand
    if subcommand not in ['log', 'show']:
        debug_print("[DEBUG] ERROR: Invalid subcommand '%s'" % subcommand)
        return "Error: Invalid subcommand '%s'. Must be 'log' or 'show'." % subcommand

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

    if repos_str:
        debug_print("[DEBUG] User specified repos: %s" % repos_str)
        # User specified repos explicitly
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

            repos_to_search.append((repo_name, repo_path))
            debug_print("[DEBUG] Added repo to search list: %s -> %s" % (repo_name, repo_path))
    else:
        debug_print("[DEBUG] Detecting RHEL version from kernel_version: %s" % kernel_version)
        # Use current RHEL version from kernel
        current_dir, current_version = get_current_rhel_dir(kernel_version)
        if not current_dir:
            debug_print("[DEBUG] ERROR: Could not detect RHEL version")
            return "Error: Could not detect RHEL version from kernel version '%s'\n" \
                   "Kernel version must contain .el5, .el6, .el7, .el8, .el9, or .el10\n" \
                   "Or RHEL_SOURCE_DIR not set" % kernel_version

        debug_print("[DEBUG] Detected version: %s -> %s" % (current_version, current_dir))
        repos_to_search.append((current_version, current_dir))

    # Add header
    results.append(BOLD_WHITE + separator + RESET)
    results.append(BOLD_WHITE + "Git %s Results" % subcommand.title() + RESET)
    results.append(CYAN + "Command: git %s %s" % (subcommand, ' '.join(git_args)) + RESET)
    results.append(CYAN + "Kernel version: %s" % kernel_version + RESET)
    results.append(BOLD_WHITE + separator + RESET)
    results.append("")

    # Execute git command in each repository
    debug_print("[DEBUG] Total repositories to search: %d" % len(repos_to_search))
    for idx, (repo_name, repo_path) in enumerate(repos_to_search, 1):
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
        debug_print("[DEBUG] Command: git %s %s" % (subcommand, ' '.join(git_args)))
        # Execute git command
        success, output = execute_git_command(repo_path, subcommand, git_args)
        debug_print("[DEBUG] execute_git_command() returned: success=%s" % success)
        if success:
            debug_print("[DEBUG] Output length: %d chars" % len(output))
            results.append(output)
        else:
            debug_print("[DEBUG] Error: %s" % output)
            results.append("Error: %s" % output)

        results.append("")

    debug_print("[DEBUG] All repositories processed. Preparing response...")

    # Add footer
    results.append(BOLD_WHITE + separator + RESET)
    results.append(BOLD_WHITE + "Complete" + RESET)
    results.append(BOLD_WHITE + separator + RESET)

    response = '\n'.join(results)
    debug_print("[DEBUG] Response prepared, length: %d chars" % len(response))
    debug_print("[DEBUG] git_command() COMPLETE - Returning response")
    debug_print("="*80 + "\n")
    return response
