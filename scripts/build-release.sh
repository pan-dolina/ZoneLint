#!/usr/bin/env bash
# Builds release archives for all supported platforms into dist/.
#
# The build is reproducible: given the same commit and Go toolchain, the
# archives and SHA256SUMS are byte-for-byte identical. Inputs that would
# otherwise vary (paths, build IDs, timestamps) are fixed:
#   - go build -trimpath, -buildvcs and CGO_ENABLED=0
#   - version metadata taken from git (tag, commit, commit date); VCS stamping
#     records the same revision in the Go build information used by SBOMs
#   - archive entries timestamped with the commit time (SOURCE_DATE_EPOCH)
#
# Environment:
#   VERSION  release version (default: exact git tag, else v0.0.0-<commit>)
#   DIST     output directory (default: dist)
set -euo pipefail

cd "$(dirname "$0")/.."

DIST="${DIST:-dist}"
COMMIT="$(git rev-parse HEAD)"
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"

toolchain="$(sed -n 's/^toolchain //p' go.mod)"
export GOTOOLCHAIN="${toolchain:-local}"
export GOENV=off GOAMD64=v1 GOARM64=v8.0 GOEXPERIMENT=
echo "toolchain: $(go version)"
DATE="$(git log -1 --format=%cI)"
VERSION="${VERSION:-$(git describe --tags --exact-match 2>/dev/null || echo "v0.0.0-${COMMIT:0:12}")}"
TARGETS="${TARGETS:-linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64}"

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "warning: working tree has uncommitted changes; the build is not reproducible from the commit" >&2
fi

pkg="github.com/example/ZoneLint/internal/version"
ldflags="-s -w -X ${pkg}.Version=${VERSION} -X ${pkg}.Commit=${COMMIT} -X ${pkg}.Date=${DATE}"

rm -rf "$DIST"
mkdir -p "$DIST"

for target in $TARGETS; do
  goos="${target%/*}"
  goarch="${target#*/}"
  name="zonelint_${VERSION#v}_${goos}_${goarch}"
  exe="zonelint"
  [ "$goos" = "windows" ] && exe="zonelint.exe"

  echo "building $name"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" GOFLAGS="${GOFLAGS:+$GOFLAGS }-mod=readonly" \
    go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$DIST/$name/$exe" ./cmd/zonelint

  ext="tar.gz"
  [ "$goos" = "windows" ] && ext="zip"
  # Include LICENSE and README.md in the archive so users get documentation
  # alongside the binary.
  [ -f LICENSE ] && cp LICENSE "$DIST/$name/LICENSE"
  [ -f README.md ] && cp README.md "$DIST/$name/README.md"

  # Reproducible archive: entries timestamped with the commit time and sorted
  # by name. Python's tarfile is used because BSD/GNU tar mtime options differ.
  chmod +x "$DIST/$name/$exe" 2>/dev/null || true
  if [ "$ext" = "zip" ]; then
    # Use Python's zipfile for reproducible timestamps; the macOS zip utility
    # embeds the current time in the archive header.
    python3 - "$SOURCE_DATE_EPOCH" "$DIST/$name" "$DIST/$name.$ext" <<'PYEOF'
import sys, zipfile, os
epoch = int(sys.argv[1])
src = sys.argv[2]
out = sys.argv[3]
files = []
for root, dirs, fnames in os.walk(src):
    dirs.sort()
    for fn in sorted(fnames):
        files.append(os.path.join(root, fn))
files.sort()
import time
dt = time.gmtime(epoch)
with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for p in files:
        st = os.lstat(p)
        arc = os.path.relpath(p, src)
        info = zipfile.ZipInfo(arc, date_time=dt)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = (st.st_mode & 0o7777) << 16
        info.external_attr |= (3 << 24)  # external OS = Unix
        with open(p, "rb") as f:
            zf.writestr(info, f.read())
PYEOF
  else
    python3 - "$SOURCE_DATE_EPOCH" "$DIST/$name" "$DIST/$name.$ext" <<'PYEOF'
import sys, tarfile, os, gzip
epoch = int(sys.argv[1])
src = sys.argv[2]
out = sys.argv[3]
files = []
for root, dirs, fnames in os.walk(src):
    dirs.sort()
    for fn in sorted(fnames):
        files.append(os.path.join(root, fn))
files.sort()
# Open the gzip stream with a fixed mtime so the archive is reproducible.
raw = open(out, "wb")
gz = gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0)
tf = tarfile.open(fileobj=gz, mode="w")
for p in files:
    st = os.lstat(p)
    ti = tarfile.TarInfo(name=os.path.relpath(p, src))
    ti.mtime = epoch
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    ti.mode = st.st_mode & 0o7777
    if os.path.islink(p):
        ti.type = tarfile.LNKTYPE
        ti.linkname = os.readlink(p)
        tf.addfile(ti)
    else:
        ti.size = st.st_size
        with open(p, "rb") as f:
            tf.addfile(ti, f)
tf.close()
gz.close()
PYEOF
  fi
  rm -rf "$DIST/$name"
done

(
  cd "$DIST"
  shopt -s nullglob
  archives=(*.tar.gz *.zip)
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "${archives[@]}" | LC_ALL=C sort -k2 > SHA256SUMS
  else
    shasum -a 256 -- "${archives[@]}" | LC_ALL=C sort -k2 > SHA256SUMS
  fi
)
echo "wrote $DIST/SHA256SUMS"
cat "$DIST/SHA256SUMS"
