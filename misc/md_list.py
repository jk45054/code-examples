# md_list.py
#
# Input: a directory
# Output: a markdown table with columns Filename, Size, SHA256 for each file
# in the directory

from Crypto.Hash import SHA256
import sys
from os import listdir
from os.path import isfile

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <directory>")
        exit()
    # start with table header
    print("Filename | Size | SHA256")
    print("--- | --- | ---")
    # iterate over all files in supplied directory
    for file in listdir(sys.argv[1]):
        filepath = sys.argv[1] + file
        # only work on files, not directories
        if isfile(filepath):
            # read file contents
            with open(filepath, "rb") as f:
                contents = f.read()
            f.close()
            # hash the contents
            h = SHA256.new()
            h.update(contents)
            # print the line
            print(f"{file} | {len(contents):,} bytes | {h.hexdigest()}")
