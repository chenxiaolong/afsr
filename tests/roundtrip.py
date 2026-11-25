#!/usr/bin/env python3

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import tomllib

PROJECT_ROOT = pathlib.Path(sys.path[0]).parent


def check_sha256(path: pathlib.Path, expected: str):
    with open(path, 'rb') as f:
        digest = hashlib.file_digest(f, 'sha256')

    actual = digest.hexdigest()
    if actual != expected:
        raise Exception(f'Expected SHA-256 {expected}, but have {actual}: {path!r}')


def diff_metadata(old_path: pathlib.Path, new_path: pathlib.Path):
    with open(old_path, 'rb') as f:
        old_info = tomllib.load(f)
        old_info['entries'].sort(key=lambda e: e['path'])

    with open(new_path, 'rb') as f:
        new_info = tomllib.load(f)

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = pathlib.Path(temp_dir)

        old_metadata = temp_path / 'old_metadata.json'
        new_metadata = temp_path / 'new_metadata.json'

        with open(old_metadata, 'w') as f:
            json.dump(old_info, f, indent=4)

        with open(new_metadata, 'w') as f:
            json.dump(new_info, f, indent=4)

        subprocess.check_call([
            'diff', '-u', '--color=auto',
            old_metadata, new_metadata,
        ])


def diff_tree(old_path: pathlib.Path, new_path: pathlib.Path):
    subprocess.check_call([
        'diff', '-Nru', '--color=auto',
        old_path, new_path,
    ])


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'afsr',
        type=pathlib.Path,
        nargs='+',
        help='Command to run afsr',
    )

    return parser.parse_args()


def main():
    args = parse_args()

    tests = PROJECT_ROOT / 'tests'

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = pathlib.Path(temp_dir)

        old_metadata = tests / 'erofs_metadata.toml'
        new_metadata = temp_path / 'erofs_metadata.toml'
        old_tree = tests / 'erofs_tree'
        new_tree = temp_path / 'erofs_tree'
        erofs_image = temp_path / 'erofs.img'

        subprocess.check_call(
            [
                *args.afsr, 'pack',
                '--input-metadata', old_metadata,
                '--input-tree', old_tree,
                '--output', erofs_image,
            ],
            cwd=PROJECT_ROOT,
        )

        check_sha256(erofs_image, '5f5f73e0ef75a92a206c7806bd0a8768a1b5e71c8ce6ba761f9ede68cd9ab30f')

        subprocess.check_call(
            [
                *args.afsr, 'unpack',
                '--input', erofs_image,
                '--output-metadata', new_metadata,
                '--output-tree', new_tree,
            ],
            cwd=PROJECT_ROOT,
        )

        diff_metadata(old_metadata, new_metadata)
        diff_tree(old_tree, new_tree)


if __name__ == '__main__':
    main()
