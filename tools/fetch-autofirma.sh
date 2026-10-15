#!/usr/bin/env bash
# Downloads the official AutoFirma and extracts the runnable jar, so we can
# produce golden files to diff our output against. See docs/validation.md.
#
# Nothing here is committed, it all lands in the directory given by
# AUTOFIRMA_DIR (default /tmp/autofirma-ref).
set -euo pipefail

VERSION="${1:-1_9_2}"
DEST="${AUTOFIRMA_DIR:-/tmp/autofirma-ref}"
BASE="https://firmaelectronica.gob.es/content/dam/firmaelectronica/descargas-software/autofirma19"

mkdir -p "$DEST"
cd "$DEST"

case "$(uname -s)" in
  Linux)  PKG="Autofirma_Linux_Debian.zip" ;;
  Darwin) PKG="Autofirma_${VERSION}_Mac_M1.zip" ;;
  *)      echo "unsupported, download it by hand from https://firmaelectronica.gob.es/descargas" >&2; exit 1 ;;
esac

if [ ! -f "$PKG" ]; then
  echo "fetching $PKG"
  curl -fSL --retry 3 -o "$PKG" "$BASE/$PKG"
fi

if [ ! -f autofirma.jar ]; then
  rm -rf extracted && mkdir -p extracted
  unzip -q -o "$PKG" -d extracted
  DEB="$(find extracted -maxdepth 1 -name '*.deb' | head -1)"
  if [ -n "$DEB" ]; then
    ( cd extracted && ar x "$DEB" && tar -xf data.tar.* )
  fi
  find extracted -name 'autofirma.jar' -exec cp {} ./autofirma.jar \;
  find extracted -name 'autofirmaConfigurador.jar' -exec cp {} ./ \; 2>/dev/null || true
fi

if [ ! -f autofirma.jar ]; then
  echo "could not find autofirma.jar, check the package layout" >&2
  exit 1
fi

echo "autofirma.jar ready at $DEST/autofirma.jar"
java -jar autofirma.jar --version 2>/dev/null || echo "(needs a JRE, AutoFirma ships one inside the deb)"
