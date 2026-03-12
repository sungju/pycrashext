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


def get_current_rhel_dir():
    """
    Determine the current RHEL source directory based on environment.

    Returns:
        tuple: (rhel_dir, version_name) e.g., ('/path/to/rhel8', 'rhel8')
    """
    try:
        base_dir = os.environ['RHEL_SOURCE_DIR']
    except KeyError:
        return None, None

    # Try to detect from current directory if possible
    # For now, we'll use a heuristic or default
    # You might want to improve this based on your setup

    # Check common RHEL versions in order of preference
    for version in ['rhel10', 'rhel9', 'rhel8', 'rhel7', 'rhel6']:
        rhel_path = os.path.join(base_dir, version)
        if os.path.isdir(rhel_path):
            return rhel_path, version

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

        # Checkout the latest
        checkout_cmd = 'git --no-pager checkout %s && git --no-pager pull origin %s' % (default_branch, default_branch)
        process = subprocess.Popen(
            checkout_cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        result = process.wait()
        out = process.stdout.read().decode('utf-8')
        err = process.stderr.read().decode('utf-8')

        os.chdir(original_dir)

        if result != 0:
            return False, "Failed to checkout latest: %s" % err

        return True, "Successfully checked out latest on branch %s" % default_branch

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
        # This limits git log --max-count to prevent searching entire history
        if max_commits == 0:
            # If user wants all commits, still limit for performance
            search_limit = 1000  # Reasonable limit for "all"
        else:
            # Use maxmatch value directly for git --max-count
            # This searches exactly the number of commits requested
            search_limit = max_commits

        # Search in commit messages and diffs
        # Use -S to search for string in diffs, --all to search all branches
        # Add --max-count to limit how far back git searches
        # Use --no-pager to output immediately without buffering
        git_cmd = 'git --no-pager log --all --oneline --source --decorate --max-count=%d' % search_limit

        # Add pickaxe search for pattern in diffs
        git_cmd += ' -S"%s"' % pattern

        # Also search in commit messages
        grep_cmd = 'git --no-pager log --all --oneline --source --decorate --max-count=%d --grep="%s"' % (search_limit, pattern)

        # Combine both searches
        combined_cmd = '{ %s; %s; } | sort -u' % (git_cmd, grep_cmd)
        print(combined_cmd)

        process = subprocess.Popen(
            combined_cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        process.wait()
        commit_list = process.stdout.read().decode('utf-8').strip()
        print(commit_list)

        if not commit_list:
            os.chdir(original_dir)
            return True, "No matching commits found"

        # Parse commit hashes
        commits = []
        for line in commit_list.split('\n'):
            if line.strip():
                # Extract just the commit hash (first field)
                match = re.match(r'^([a-f0-9]+)', line)
                if match:
                    commits.append(match.group(1))

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

            results.append(commit_detail)

        os.chdir(original_dir)

        # Format final output
        separator = "=" * 80
        output = []

        for i, result in enumerate(results, 1):
            output.append("%s\nCommit %d/%d\n%s" % (separator, i, len(results), separator))
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


def gitsearch():
    """
    Main gitsearch endpoint handler.

    Searches git log in kernel source repositories for matching commits.
    """
    # Get parameters from request
    try:
        pattern = request.form['pattern']
        lines = int(request.form.get('lines', 20))
        maxmatch = int(request.form.get('maxmatch', 5))
        extraversion = request.form.get('extraversion', '')
        verbose = request.form.get('verbose', 'False') == 'True'
        show_context = request.form.get('context', 'False') == 'True'
        kernel_version = request.form.get('kernel_version', 'unknown')
    except Exception as e:
        return "Error parsing request parameters: %s" % str(e)

    # Get base RHEL source directory
    current_dir, current_version = get_current_rhel_dir()
    if not current_dir:
        return "Error: RHEL_SOURCE_DIR not set or no RHEL directories found"

    results = []
    separator = "=" * 80

    # Determine actual search limit for display
    display_limit = 1000 if maxmatch == 0 else maxmatch

    # Add header
    results.append(separator)
    results.append("Git Log Search Results")
    results.append("Search pattern: %s" % pattern)
    results.append("Kernel version: %s" % kernel_version)
    results.append("Max commits (git --max-count): %s" % ('1000' if maxmatch == 0 else maxmatch))
    results.append("Max lines per commit: %s" % ('all' if lines == 0 else lines))
    results.append(separator)
    results.append("")

    # Search in current version
    results.append("[Searching in %s]" % current_version)

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
                results.append("[%s] Directory not found: %s" % (version, version_path))
                results.append("")
                continue

            results.append(separator)
            results.append("[Searching in %s]" % version)

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

    # Add footer
    results.append(separator)
    results.append("Search complete")
    results.append(separator)

    return '\n'.join(results)
