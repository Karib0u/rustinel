# Benign behavior generator for the golden replay fixture.
#
# Run this on a Windows lab endpoint while `rustinel capture` is recording to
# produce the same shape of behavior as the checked-in recording next to it:
# an encoded PowerShell launch followed by a file write to the user's temp
# directory. Everything it does is harmless — it prints a string and writes a
# text file — but it exercises the two field paths the fixture Sigma rules
# match on.
#
#   rustinel capture --output .\windows-powershell.ndjson
#   powershell -ExecutionPolicy Bypass -File .\windows-powershell-fixture.ps1
#   # Ctrl-C the capture
#
# Regenerating the checked-in recording is described in docs/detection.md.

$ErrorActionPreference = 'Stop'

# 'Write-Output ''rustinel replay fixture''' encoded as UTF-16LE base64, which
# is what -EncodedCommand takes.
$encoded = 'VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAHIAdQBzAHQAaQBuAGUAbAAgAHIAZQBwAGwAYQB5ACAAZgBpAHgAdAB1AHIAZQAnAA=='

powershell.exe -NoProfile -EncodedCommand $encoded

$marker = Join-Path $env:TEMP 'rustinel-replay-fixture.txt'
Set-Content -Path $marker -Value 'rustinel replay fixture'
