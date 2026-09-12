"""Keep Markdown at one sentence per line.

    python3 scripts/docs/reflow.py docs/*.md README.md CONTRIBUTING.md
    python3 scripts/docs/reflow.py --check docs/*.md README.md CONTRIBUTING.md

Rewrites paragraphs and list items so a line ends only where a sentence ends.
Fenced code, tables, headings, HTML blocks, admonition and tab markers, and
generated regions are left alone. Only line breaks change: a file whose text
would differ after collapsing whitespace is refused. `--check` rewrites nothing
and exits non-zero when a file needs reflowing.
"""
import re
import sys

LIST = re.compile(r'^(\s*)([-*+]|\d+\.)(\s+)')
FENCE = re.compile(r'^\s*(```+|~~~+)')
HTML = re.compile(r'^\s*<(/?(p|img|h1|h2|div|br|table|details|summary)\b|!--)')
SPLIT = re.compile(
    r'(?:(?<=[.!?])|(?<=[.!?]\*\*)|(?<=[.!?]\))|(?<=[.!?]"))\s+(?=[A-Z0-9`*\[("\x00])'
)


def passthrough(line):
    s = line.strip()
    return (
        not s
        or s.startswith('#')
        or s.startswith('|')
        or s.startswith('!!!')
        or s.startswith('===')
        or s in ('---', '***')
        or HTML.match(line) is not None
    )


def sentences(text):
    spans = []

    def keep(match):
        spans.append(match.group(0))
        return f'\x00{len(spans) - 1}\x00'

    protected = re.sub(r'`[^`]*`', keep, text)
    parts = SPLIT.split(protected)
    restore = lambda part: re.sub(r'\x00(\d+)\x00', lambda m: spans[int(m.group(1))], part)
    return [restore(part) for part in parts if part]


def reflow(text):
    lines = text.split('\n')
    out = []
    i = 0
    fence = None
    generated = False
    html = False
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if 'BEGIN GENERATED' in stripped:
            generated = True
        if generated:
            out.append(line)
            if 'END GENERATED' in stripped:
                generated = False
            i += 1
            continue
        if fence:
            out.append(line)
            if stripped.startswith(fence):
                fence = None
            i += 1
            continue
        match = FENCE.match(line)
        if match:
            fence = match.group(1)
            out.append(line)
            i += 1
            continue
        if html or HTML.match(line):
            html = bool(stripped)
            out.append(line)
            i += 1
            continue
        if passthrough(line):
            out.append(line)
            i += 1
            continue

        block = [line]
        j = i + 1
        while (
            j < len(lines)
            and not passthrough(lines[j])
            and not FENCE.match(lines[j])
            and not LIST.match(lines[j])
            and 'BEGIN GENERATED' not in lines[j]
        ):
            block.append(lines[j])
            j += 1

        marker = LIST.match(block[0])
        if marker:
            prefix = marker.group(0)
            first = block[0][len(prefix):].strip()
        else:
            prefix = block[0][: len(block[0]) - len(block[0].lstrip())]
            first = block[0].strip()
        indent = ' ' * len(prefix)
        text_block = ' '.join([first] + [l.strip() for l in block[1:]])
        for n, sentence in enumerate(sentences(text_block)):
            out.append((prefix if n == 0 else indent) + sentence)
        i = j
    return '\n'.join(out)


def normalized(text):
    return ' '.join(text.split())


def main(argv):
    check = '--check' in argv
    paths = [arg for arg in argv if arg != '--check']
    stale = []
    for path in paths:
        with open(path, encoding='utf-8') as handle:
            original = handle.read()
        updated = reflow(original)
        if normalized(original) != normalized(updated):
            sys.exit(f'{path}: reflow would change the text, refusing')
        if updated == original:
            continue
        stale.append(path)
        if not check:
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write(updated)
            print(f'reflowed {path}')
    if check and stale:
        for path in stale:
            print(f'{path}: a line breaks in the middle of a sentence')
        sys.exit('run: python3 scripts/docs/reflow.py ' + ' '.join(stale))


if __name__ == '__main__':
    main(sys.argv[1:])
