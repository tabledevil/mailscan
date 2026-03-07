import hashlib
import argparse
import sys

try:
    import libarchive
except ImportError:
    sys.stderr.write('The libarchive package is missing. Please install libarchive-c first.\n')
    sys.exit(1)

parser = argparse.ArgumentParser()
parser.add_argument('infile', nargs="+")
parser.add_argument('-c', '--hashtype', default="md5", choices=hashlib.algorithms_available)
args = parser.parse_args()

def hash_files_in_archive(archive_path):
    try:
        # Open the archive file for reading
        with libarchive.file_reader(archive_path) as archive:
            # Iterate over each entry (file) in the archive
            for entry in archive:
                # Create a new hasher object using the provided hash type
                hasher = hashlib.new(args.hashtype)

                # Read the entry's data in blocks and update the hash accordingly
                for block in entry.get_blocks():
                    hasher.update(block)
                
                # Print out the resulting hexadecimal digest and the pathname of the entry
                print(f'{hasher.hexdigest()}  {entry.pathname}')
    except AttributeError:
        sys.stderr.write("It seems you're using a version of libarchive that doesn't have the 'file_reader' attribute.\n"
                         "This script requires 'python-libarchive-c'. Please ensure it's installed.\n")
        sys.exit(2)
        

# Process each input file
for infile in args.infile:
    try:
        # Open the archive and process each entry
        hash_files_in_archive(infile)
    except libarchive.exception.ArchiveError as e:
        # If file is not an archive, just print the error and continue
        print(f'Failed to open archive file {infile}: {e}', file=sys.stderr)

