import os
import argparse
from colorama import init, Fore

"""
Script to search and replace UTF-16 strings in bins.

This is not a final form revision. Only for testing right now. 
Not sure if just GSCore.dll is responsible or more dlls/exes need to be patched
This will patch out the domains with localhost on any binary input. 

Usage:
    python gsMRI_StrReplace.py -f <path_to_binary_file>

    This script will automatically search for and replace the following in the specified binary file:
    - geeksquadcentral.com -> localhost.com
    - geeksquadlabs.com -> localhost.com

Example:
    python gsMRI_StrReplace.py -f GSCore.dll

The file will be modified in place, and all occurrences of the keywords will be replaced with 'localhost.com'.
"""

init(autoreset=True)

REPLACEMENTS = {
    'geeksquadcentral.com': 'localhost.com',
    'geeksquadlabs.com': 'localhost.com'
}

def replace_in_binary(file_path, keyword, replace_word):
    keyword_bytes = keyword.encode('utf-16le')
    replace_bytes = replace_word.encode('utf-16le')

    if len(replace_bytes) > len(keyword_bytes):
        print(f"{Fore.RED}[ERROR] The replacement string '{replace_word}' is longer than the original string '{keyword}'.")
        return False

    with open(file_path, 'rb') as f:
        binary_data = f.read()

    occurrences = binary_data.count(keyword_bytes)
    if occurrences == 0:
        print(f"{Fore.YELLOW}[WARNING] No occurrences of '{keyword}' (UTF-16) found in the binary.")
        return False

    print(f"{Fore.GREEN}[INFO] Found {occurrences} occurrences of '{keyword}' (UTF-16).")

    modified_binary_data = binary_data.replace(keyword_bytes, replace_bytes + b'\x00' * (len(keyword_bytes) - len(replace_bytes)))

    with open(file_path, 'wb') as f:
        f.write(modified_binary_data)

    print(f"{Fore.GREEN}[SUCCESS] Replaced occurrences of '{keyword}' with '{replace_word}' in the binary.")
    return True

def main(file_path):
    if not os.path.isfile(file_path):
        print(f"{Fore.RED}[ERROR] File '{file_path}' does not exist!")
        return

    for keyword, replace_word in REPLACEMENTS.items():
        replace_in_binary(file_path, keyword, replace_word)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Search and replace predefined UTF-16 encoded keywords directly in binary files.")
    parser.add_argument("-f", "--file", help="Path to the binary file", required=True)
    
    args = parser.parse_args()

    main(args.file)
