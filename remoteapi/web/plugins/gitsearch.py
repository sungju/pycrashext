"""
Written by Daniel Sungju Kwon

Server-side plugin for searching git log in kernel source repositories
"""

from flask import Flask, request
import os
import subprocess
import re


def add_plugin_rule(app):
    """Register the gitsearch API endpoint"""
    app.add_url_rule('/api/gitsearch', 'gitsearch', gitsearch, methods=['POST'])


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
    try:
        original_dir = os.getcwd()
        os.chdir(repo_path)

        # Get the default branch (usually main or master)
        branch_process = subprocess.Popen(
            'git --no-pager remote show origin | grep "HEAD branch" | cut -d: -f2',
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        branch_process.wait()
        default_branch = branch_process.stdout.read().decode('utf-8').strip()

        if not default_branch:
            # Fallback to common branch names
            for branch in ['main', 'master', 'trunk']:
                check_process = subprocess.Popen(
                    'git --no-pager rev-parse --verify %s' % branch,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                if check_process.wait() == 0:
                    default_branch = branch
                    break

        if not default_branch:
            default_branch = 'master'  # Ultimate fallback

        # Fetch latest changes (doesn't require clean working directory)
        fetch_cmd = 'git --no-pager fetch origin %s' % default_branch
        fetch_process = subprocess.Popen(
            fetch_cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        fetch_result = fetch_process.wait()
        fetch_err = fetch_process.stderr.read().decode('utf-8')

        if fetch_result != 0:
            os.chdir(original_dir)
            return False, "Failed to fetch: %s" % fetch_err

        # Reset to latest (discards any local changes - safe for read-only source repos)
        reset_cmd = 'git --no-pager checkout -f %s && git --no-pager reset --hard origin/%s' % (default_branch, default_branch)
        reset_process = subprocess.Popen(
            reset_cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        reset_result = reset_process.wait()
        reset_out = reset_process.stdout.read().decode('utf-8')
        reset_err = reset_process.stderr.read().decode('utf-8')

        os.chdir(original_dir)

        if reset_result != 0:
            return False, "Failed to reset to latest: %s" % reset_err

        return True, "Successfully updated to latest on branch %s" % default_branch

    except Exception as e:
        try:
            os.chdir(original_dir)
        except:
            pass
        return False, "Exception during checkout: %s" % str(e)


def search_git_log(repo_path, pattern, max_lines=20, max_commits=5, show_context=False):
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
        # Use --format=%H to get just commit hashes, one per line
        git_cmd = 'git --no-pager log --format=%%H --grep="%s" --max-count=%d' % (pattern, search_limit)

        process = subprocess.Popen(
            git_cmd,
            shell=True,
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
            # Get commit details
            show_cmd = 'git --no-pager show --stat %s' % commit

            if show_context:
                show_cmd = 'git --no-pager show %s' % commit

            detail_process = subprocess.Popen(
                show_cmd,
                shell=True,
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

        # Show full commit content
        git_cmd = 'git --no-pager show %s' % commit_id

        process = subprocess.Popen(
            git_cmd,
            shell=True,
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


def gitsearch():
    """
    Main gitsearch endpoint handler.

    Searches git log in kernel source repositories for matching commits.
    """
    # Get parameters from request
    try:
        pattern = request.form.get('pattern', '')
        lines = int(request.form.get('lines', 20))
        maxmatch = int(request.form.get('maxmatch', 5))
        extraversion = request.form.get('extraversion', '')
        verbose = request.form.get('verbose', 'False') == 'True'
        show_context = request.form.get('context', 'False') == 'True'
        kernel_version = request.form.get('kernel_version', 'unknown')
        commit_id = request.form.get('commit', '')
    except Exception as e:
        return "Error parsing request parameters: %s" % str(e)

    # Handle --commit option (show specific commit)
    if commit_id:
        # Color constants
        BOLD_WHITE = "\033[1;37m"
        CYAN = "\033[36m"
        RESET = "\033[0m"

        results = []
        separator = "=" * 80

        # Determine which directory to use
        if extraversion:
            # User specified a specific version (e.g., rhel8, rhel9, linux, etc.)
            try:
                base_dir = os.environ['RHEL_SOURCE_DIR']
                repo_path = os.path.join(base_dir, extraversion)
                version_name = extraversion
            except KeyError:
                return "Error: RHEL_SOURCE_DIR environment variable not set"

            if not os.path.isdir(repo_path):
                return "Error: Directory not found: %s" % repo_path
        else:
            # Use current RHEL version from kernel
            current_dir, current_version = get_current_rhel_dir(kernel_version)
            if not current_dir:
                return "Error: Could not detect RHEL version from kernel version '%s'\n" \
                       "Kernel version must contain .el5, .el6, .el7, .el8, .el9, or .el10\n" \
                       "Or RHEL_SOURCE_DIR not set" % kernel_version
            repo_path = current_dir
            version_name = current_version

        # Add header with colors
        results.append(BOLD_WHITE + separator + RESET)
        results.append(BOLD_WHITE + "Git Commit Details" + RESET)
        results.append(CYAN + "Commit ID: %s" % commit_id + RESET)
        results.append(CYAN + "Repository: %s" % version_name + RESET)
        results.append(BOLD_WHITE + separator + RESET)
        results.append("")

        if verbose:
            results.append("Checking out latest code...")

        success, msg = git_checkout_latest(repo_path)
        if not success:
            results.append("Warning: %s" % msg)
        elif verbose:
            results.append(msg)

        # Show the commit
        success, commit_content = show_commit(repo_path, commit_id)
        if success:
            results.append(commit_content)
        else:
            results.append(commit_content)  # Error message

        # Add footer with colors
        results.append("")
        results.append(BOLD_WHITE + separator + RESET)

        return '\n'.join(results)

    # Regular search (no --commit option)
    # Get base RHEL source directory (detect from kernel version)
    current_dir, current_version = get_current_rhel_dir(kernel_version)
    if not current_dir:
        return "Error: Could not detect RHEL version from kernel version '%s'\n" \
               "Kernel version must contain .el5, .el6, .el7, .el8, .el9, or .el10\n" \
               "Or RHEL_SOURCE_DIR not set" % kernel_version

    # Color constants
    BOLD_WHITE = "\033[1;37m"
    CYAN = "\033[36m"
    YELLOW = "\033[33m"
    RESET = "\033[0m"

    results = []
    separator = "=" * 80

    # Determine actual search limit for display
    display_limit = 1000 if maxmatch == 0 else maxmatch

    # Add header with colors
    results.append(BOLD_WHITE + separator + RESET)
    results.append(BOLD_WHITE + "Git Log Search Results" + RESET)
    results.append(CYAN + "Search pattern: %s" % pattern + RESET)
    results.append(CYAN + "Kernel version: %s" % kernel_version + RESET)
    results.append(CYAN + "Max commits (git --max-count): %s" % ('1000' if maxmatch == 0 else maxmatch) + RESET)
    results.append(CYAN + "Max lines per commit: %s" % ('all' if lines == 0 else lines) + RESET)
    results.append(BOLD_WHITE + separator + RESET)
    results.append("")

    # Search in current version
    results.append(YELLOW + "[Searching in %s]" % current_version + RESET)

    if verbose:
        results.append("Checking out latest code...")

    success, msg = git_checkout_latest(current_dir)
    if not success:
        results.append("Warning: %s" % msg)
    elif verbose:
        results.append(msg)

    if verbose:
        results.append("Searching git log...")

    success, search_results = search_git_log(current_dir, pattern, lines, maxmatch, show_context)
    results.append(search_results)
    results.append("")

    # Search in extra versions if specified
    if extraversion:
        base_dir = os.path.dirname(current_dir)
        extra_versions = [v.strip() for v in extraversion.split(',')]

        for version in extra_versions:
            version_path = os.path.join(base_dir, version)

            if not os.path.isdir(version_path):
                results.append(YELLOW + "[%s] Directory not found: %s" % (version, version_path) + RESET)
                results.append("")
                continue

            results.append(BOLD_WHITE + separator + RESET)
            results.append(YELLOW + "[Searching in %s]" % version + RESET)

            if verbose:
                results.append("Checking out latest code...")

            success, msg = git_checkout_latest(version_path)
            if not success:
                results.append("Warning: %s" % msg)
            elif verbose:
                results.append(msg)

            if verbose:
                results.append("Searching git log...")

            success, search_results = search_git_log(version_path, pattern, lines, maxmatch, show_context)
            results.append(search_results)
            results.append("")

    # Add footer with colors
    results.append(BOLD_WHITE + separator + RESET)
    results.append(BOLD_WHITE + "Search complete" + RESET)
    results.append(BOLD_WHITE + separator + RESET)

    return '\n'.join(results)
