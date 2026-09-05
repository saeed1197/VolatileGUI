#!/usr/bin/env bash
# Fetch a public memory sample into ./evidence/ so you have something to analyse.
#
#   ./scripts/fetch_sample.sh                 # print known sources
#   ./scripts/fetch_sample.sh <url> [name]    # download one
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$HERE/evidence"
mkdir -p "$DEST"

if [ $# -eq 0 ]; then
  cat <<'EOF'
Public memory images that work well with this platform
------------------------------------------------------

  Volatility Foundation sample gallery (Windows XP -> 10, Linux, Mac; several
  carry real malware and are the images most walkthroughs use):
    https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples

  MemLabs — six CTF-style Windows images with a full write-up:
    https://github.com/stuxnet999/MemLabs

  Ali Hadi's DFIR challenges — Windows images with documented answers:
    https://www.ashemery.com/dfir.html

Usage:
  ./scripts/fetch_sample.sh <direct-url> [output-name]

Then open the web UI and press "Scan evidence folder".
EOF
  exit 0
fi

URL="$1"
NAME="${2:-$(basename "${URL%%\?*}")}"
OUT="$DEST/$NAME"

echo "→ downloading $URL"
echo "→ into        $OUT"
if command -v curl >/dev/null 2>&1; then
  curl -L --fail --progress-bar -o "$OUT" "$URL"
else
  wget --show-progress -O "$OUT" "$URL"
fi

case "$NAME" in
  *.zip)
    echo "→ archive detected; extracting"
    (cd "$DEST" && unzip -o "$NAME" && rm -f "$NAME")
    ;;
  *.7z)
    echo "→ 7z archive: extract it yourself with 7z x '$OUT' -o'$DEST'"
    ;;
  *.gz)
    echo "→ gunzipping"
    gunzip -f "$OUT"
    ;;
esac

echo
echo "Done. Files now in evidence/:"
ls -lh "$DEST"
echo
echo "Open the web UI and click 'Scan evidence folder' to register them."
