import argparse
from pathlib import Path
from PIL import Image
import json

def get_allexif_asjson(image):
  """Returns all EXIF data as a JSON string."""
  exif = image._getexif()
  if not exif:
    return None
  return json.dumps(dict(exif), indent=2)

def get_exif(path):
    image = Image.open(path)
    return get_allexif_asjson(image)

def main():
    parser = argparse.ArgumentParser(description='Enumerate all files in folder and subfolders that are supported by the vHash function')
    parser.add_argument('paths', nargs='+', help='Paths to folders or files')
    args = parser.parse_args()

    # File extensions supported by the vHash function
    supported_extensions = ['.jpg', '.jpeg', '.png', '.tif', '.tiff', '.gif', '.dng', '.cr2', '.nef']

    paths = []
    for path in args.paths:
        if Path(path).is_dir():
            for ext in supported_extensions:
                paths += list(Path(path).rglob(f'*{ext}'))
        else:
            if any(path.lower().endswith(ext) for ext in supported_extensions):
                paths.append(Path(path))

    return paths

if __name__ == '__main__':
    supported_paths = main()
    for path in supported_paths:
        print(get_exif(path))
