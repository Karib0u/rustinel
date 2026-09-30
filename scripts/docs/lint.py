"""Check the writing rules in CONTRIBUTING.md that a script can check.

    python3 scripts/docs/lint.py docs/*.md

Fails on dates, Rustinel issue or PR references, em dashes, and source paths
outside the Contributing pages, and on pages over 300 lines. Fenced code,
inline code (except for em dashes), and generated regions are not checked.
"""
import re
import sys
from pathlib import Path

CONTRIBUTING_PAGES = {'development.md', 'architecture.md', 'benchmarking.md'}
MAX_LINES = 300

FENCE = re.compile(r'^\s*(```+|~~~+)')
INLINE_CODE = re.compile(r'`[^`]*`')
LINK = re.compile(r'\[([^\]]*)\]\(([^)]*)\)')
DATE = re.compile(r'\b20\d\d-\d\d-\d\d\b')
ISSUE_WORD = re.compile(r'\b(?:issues?|PRs?|pull requests?)\s+#?\d+', re.IGNORECASE)
OWN_ISSUE_URL = re.compile(r'github\.com/Karib0u/rustinel/(?:issues|pull)/\d+')
BARE_REF = re.compile(r'(?<![\w/&])#\d+\b')
SOURCE_PATH = re.compile(r'\bsrc/')


def prose_lines(text):
    """Yield (number, line, in_generated) for lines outside fenced code."""
    fence = None
    generated = False
    for number, line in enumerate(text.split('\n'), 1):
        if 'BEGIN GENERATED' in line:
            generated = True
        if 'END GENERATED' in line:
            generated = False
            continue
        match = FENCE.match(line)
        if match:
            marker = match.group(1)[0] * 3
            if fence is None:
                fence = marker
            elif marker == fence:
                fence = None
            continue
        if fence is None:
            yield number, line, generated


def check(path):
    text = path.read_text(encoding='utf-8')
    problems = []
    counted = 0
    for number, line, generated in prose_lines(text):
        if generated:
            continue
        counted += 1
        if '\u2014' in line:
            problems.append((number, 'em dash: use a comma, colon, or new sentence'))
        prose = INLINE_CODE.sub('', line)
        if DATE.search(prose):
            problems.append((number, 'date: history and lab runs go in the PR or release notes'))
        # Link text such as "SEP #212" may cite a third-party tracker.
        unlinked = LINK.sub(lambda m: m.group(2), prose)
        if OWN_ISSUE_URL.search(prose) or ISSUE_WORD.search(prose) or BARE_REF.search(unlinked):
            problems.append((number, 'issue or PR reference: describe current behavior instead'))
        if path.name not in CONTRIBUTING_PAGES and SOURCE_PATH.search(prose):
            problems.append((number, 'source path: keep code locations on the Contributing pages'))
    if counted > MAX_LINES:
        problems.append((0, f'{counted} lines, over {MAX_LINES}: split the page or move detail to a reference page'))
    return problems


def main(paths):
    failed = False
    for name in paths:
        for number, message in check(Path(name)):
            failed = True
            print(f'{name}:{number}: {message}')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
