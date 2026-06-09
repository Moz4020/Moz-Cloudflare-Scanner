#!/usr/bin/env sh
set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

sh "$script_dir/build-linux.sh"

version="0.1.2"
version_file_friendly="$(printf '%s' "$version" | tr ' ' '-')"
dist="$script_dir/dist"
package_dir="$dist/release-package-linux"
archive_path="$dist/moz-cloudflare-scanner-linux-amd64-$version_file_friendly.tar.gz"

rm -rf "$package_dir"
mkdir -p "$package_dir"

cp "$dist/moz-cloudflare-scanner-linux-amd64" "$package_dir/"
cp "$script_dir/README.md" "$package_dir/"
cp "$script_dir/LICENSE" "$package_dir/"

rm -f "$archive_path"
tar -C "$package_dir" -czf "$archive_path" .
rm -rf "$package_dir"

printf 'Created %s\n' "$archive_path"
