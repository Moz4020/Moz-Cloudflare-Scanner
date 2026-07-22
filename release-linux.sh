#!/usr/bin/env sh
set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

sh "$script_dir/build-linux.sh"

version="1.2"
version_file_friendly="$(printf '%s' "$version" | tr ' ' '-')"
dist="$script_dir/dist"
package_dir="$dist/release-package-linux"
archive_path="$dist/moz-cloudflare-scanner-linux-amd64-$version_file_friendly.tar.gz"
zip_archive_path="$dist/moz-cloudflare-scanner-linux-amd64-$version_file_friendly.zip"

rm -rf "$package_dir"
mkdir -p "$package_dir"

cp "$dist/moz-cloudflare-scanner-linux-amd64" "$package_dir/"
cp "$script_dir/README.md" "$package_dir/"
cp "$script_dir/LICENSE" "$package_dir/"

rm -f "$archive_path"
tar -C "$package_dir" -czf "$archive_path" .

rm -f "$zip_archive_path"
if command -v zip >/dev/null 2>&1; then
	(
		cd "$package_dir"
		zip -q -r "$zip_archive_path" . -x '*.DS_Store'
	)
else
	printf 'zip command not found; Linux .zip archive was not created\n' >&2
	exit 1
fi
rm -rf "$package_dir"

printf 'Created %s\n' "$archive_path"
printf 'Created %s\n' "$zip_archive_path"
