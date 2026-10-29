#!/bin/sh
# Builds "Nebula Node.app" (Apple silicon and Intel) with a universal nebctl
# inside, ad-hoc signed, and zips it for a release.
# Usage: macos/build.sh VERSION OUTDIR
set -eu

version=${1:?version, e.g. v0.4.0}
out=${2:?output directory}
here=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$here")
mkdir -p "$out"
out=$(cd "$out" && pwd)
app="$out/Nebula Node.app"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# nebctl for both architectures, joined into one file.
for arch in arm64 amd64; do
	(cd "$repo" && CGO_ENABLED=0 GOOS=darwin GOARCH=$arch \
		go build -ldflags "-s -w -X main.version=$version" -o "$work/nebctl-$arch" .)
done
lipo -create -output "$work/nebctl" "$work/nebctl-arm64" "$work/nebctl-amd64"

(cd "$here" && swift build -c release --arch arm64 --arch x86_64)
bin=$(cd "$here" && swift build -c release --arch arm64 --arch x86_64 --show-bin-path)

rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$bin/NebulaNode" "$app/Contents/MacOS/NebulaNode"
cp "$work/nebctl" "$app/Contents/Resources/nebctl"
short=${version#v}
cat > "$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key><string>NebulaNode</string>
	<key>CFBundleIdentifier</key><string>net.nebctl.node</string>
	<key>CFBundleName</key><string>Nebula Node</string>
	<key>CFBundleDisplayName</key><string>Nebula Node</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleShortVersionString</key><string>$short</string>
	<key>CFBundleVersion</key><string>$short</string>
	<key>LSMinimumSystemVersion</key><string>14.0</string>
	<key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
	<key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
EOF

# Ad-hoc signatures: Apple silicon runs nothing unsigned. Not notarized, so
# a downloaded copy needs its quarantine flag cleared (see the README).
codesign --force --sign - "$app/Contents/Resources/nebctl"
codesign --force --sign - "$app"

rm -f "$out/NebulaNode-macos.zip"
(cd "$out" && ditto -c -k --keepParent "Nebula Node.app" NebulaNode-macos.zip)
echo "$app"
echo "$out/NebulaNode-macos.zip"
