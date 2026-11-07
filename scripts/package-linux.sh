#!/usr/bin/env bash
# Personal and Educational Free License (PEF License / PEFL)
# Version 1.0 - 2026-05-26
# Copyright (c) 2026 Rubens Rainelli
#
# Contact Details:
#   Email: rubens@rainelli.it
#   GitHub: https://github.com/RubensRainelli/
#   Tel: (+39) 342 811 5882
#
# Personal and educational free use permitted.
# Corporate, business or enterprise use prohibited without written authorization and fee.
# The full license can be found in the LICENSE file.
#
# Local & CI Linux Packaging Script for Warp IM:
#   1. Clean Linux Source Archive: dist/linux/warp-im-<version>-linux-sources.tar.gz
#   2. Debian Native Package:      dist/linux/warp-im_<version>_amd64.deb
#   3. AppDir & AppImage Bundle:   dist/linux/Warp_IM.AppDir (& Warp_IM-<version>-x86_64.AppImage)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

VERSION="0.1.0"
ARCH_DEB="amd64"
BUILD_APPIMAGE=0
PROFILE="release"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="$2"
      shift 2
      ;;
    --arch)
      ARCH_DEB="$2"
      shift 2
      ;;
    --build-appimage)
      BUILD_APPIMAGE=1
      shift
      ;;
    --debug)
      PROFILE="debug"
      shift
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

OUT_DIR="${ROOT_DIR}/dist/linux"
rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

echo "=================================================================="
echo " 🚀 Warp IM — Linux Packaging Pipeline (v${VERSION})"
echo " ⚖️  License: PEFL v1.0 — Copyright (c) 2026 Rubens Rainelli"
echo "=================================================================="

# ------------------------------------------------------------------------------
# 1. Build Linux Sources Archive (Clean, excluding .private/, target/, dist/, .git/)
# ------------------------------------------------------------------------------
SRC_STAGE_NAME="warp-im-${VERSION}-linux-sources"
SRC_TARBALL="${OUT_DIR}/${SRC_STAGE_NAME}.tar.gz"
echo "📦 [1/4] Creating clean Linux source archive: ${SRC_TARBALL}"

tar --exclude='./.git' \
    --exclude='./.private' \
    --exclude='./target' \
    --exclude='./dist' \
    --transform="s,^\.,${SRC_STAGE_NAME}," \
    -czf "${SRC_TARBALL}" .

# ------------------------------------------------------------------------------
# 2. Compile Native Binary (warp-app -> warp-im)
# ------------------------------------------------------------------------------
echo "🦀 [2/4] Building warp-app (${PROFILE})..."
if [[ "${PROFILE}" == "release" ]]; then
  cargo build --release -p warp-app
  BIN_PATH="${ROOT_DIR}/target/release/warp-app"
else
  cargo build -p warp-app
  BIN_PATH="${ROOT_DIR}/target/debug/warp-app"
fi

# ------------------------------------------------------------------------------
# 3. Assemble & Build Native Debian Package (warp-im_<version>_amd64.deb)
# ------------------------------------------------------------------------------
DEB_NAME="warp-im_${VERSION}_${ARCH_DEB}"
DEB_ROOT="${OUT_DIR}/${DEB_NAME}"
echo "🐧 [3/4] Building Debian package: ${OUT_DIR}/${DEB_NAME}.deb"

mkdir -p "${DEB_ROOT}/DEBIAN"
mkdir -p "${DEB_ROOT}/usr/bin"
mkdir -p "${DEB_ROOT}/usr/share/applications"
mkdir -p "${DEB_ROOT}/usr/share/icons/hicolor/scalable/apps"
mkdir -p "${DEB_ROOT}/usr/share/doc/warp-im"
mkdir -p "${DEB_ROOT}/usr/share/warp-im/themes"

cp "${BIN_PATH}" "${DEB_ROOT}/usr/bin/warp-im"
chmod 0755 "${DEB_ROOT}/usr/bin/warp-im"

cp "${ROOT_DIR}/packaging/linux/warp-im.desktop" "${DEB_ROOT}/usr/share/applications/warp-im.desktop"
cp "${ROOT_DIR}/packaging/linux/warp-im.svg" "${DEB_ROOT}/usr/share/icons/hicolor/scalable/apps/warp-im.svg"
cp "${ROOT_DIR}/LICENSE" "${DEB_ROOT}/usr/share/doc/warp-im/copyright"
cp "${ROOT_DIR}/LICENSE" "${DEB_ROOT}/usr/share/doc/warp-im/LICENSE"
cp "${ROOT_DIR}/LICENSE.it" "${DEB_ROOT}/usr/share/doc/warp-im/LICENSE.it"
cp "${ROOT_DIR}/NOTICE.md" "${DEB_ROOT}/usr/share/doc/warp-im/NOTICE.md"
cp -r "${ROOT_DIR}/themes/"* "${DEB_ROOT}/usr/share/warp-im/themes/"

sed -e "s/{{VERSION}}/${VERSION}/g" \
    -e "s/{{ARCH}}/${ARCH_DEB}/g" \
    "${ROOT_DIR}/packaging/debian/control" > "${DEB_ROOT}/DEBIAN/control"

chmod -R go-w "${DEB_ROOT}"
chmod 0755 "${DEB_ROOT}" "${DEB_ROOT}/DEBIAN" "${DEB_ROOT}/usr/bin/warp-im"
chmod 0644 "${DEB_ROOT}/DEBIAN/control"

dpkg-deb --root-owner-group --build "${DEB_ROOT}" "${OUT_DIR}/${DEB_NAME}.deb"
rm -rf "${DEB_ROOT}"

# ------------------------------------------------------------------------------
# 4. Assemble AppDir & (Optionally) Build Standalone AppImage
# ------------------------------------------------------------------------------
APPDIR="${OUT_DIR}/Warp_IM.AppDir"
echo "📦 [4/4] Assembling AppImage directory: ${APPDIR}"

mkdir -p "${APPDIR}/usr/bin"
mkdir -p "${APPDIR}/usr/share/applications"
mkdir -p "${APPDIR}/usr/share/icons/hicolor/scalable/apps"
mkdir -p "${APPDIR}/usr/share/doc/warp-im"
mkdir -p "${APPDIR}/usr/share/warp-im/themes"

cp "${BIN_PATH}" "${APPDIR}/usr/bin/warp-im"
chmod 0755 "${APPDIR}/usr/bin/warp-im"

cp "${ROOT_DIR}/packaging/linux/AppRun" "${APPDIR}/AppRun"
chmod 0755 "${APPDIR}/AppRun"

cp "${ROOT_DIR}/packaging/linux/warp-im.desktop" "${APPDIR}/warp-im.desktop"
cp "${ROOT_DIR}/packaging/linux/warp-im.desktop" "${APPDIR}/usr/share/applications/warp-im.desktop"
cp "${ROOT_DIR}/packaging/linux/warp-im.svg" "${APPDIR}/warp-im.svg"
cp "${ROOT_DIR}/packaging/linux/warp-im.svg" "${APPDIR}/.DirIcon"
cp "${ROOT_DIR}/packaging/linux/warp-im.svg" "${APPDIR}/usr/share/icons/hicolor/scalable/apps/warp-im.svg"
cp "${ROOT_DIR}/LICENSE" "${APPDIR}/usr/share/doc/warp-im/LICENSE"
cp "${ROOT_DIR}/LICENSE.it" "${APPDIR}/usr/share/doc/warp-im/LICENSE.it"
cp "${ROOT_DIR}/NOTICE.md" "${APPDIR}/usr/share/doc/warp-im/NOTICE.md"
cp -r "${ROOT_DIR}/themes/"* "${APPDIR}/usr/share/warp-im/themes/"

if [[ "${BUILD_APPIMAGE}" -eq 1 ]] && command -v appimagetool >/dev/null 2>&1; then
  echo "🔧 Generating standalone AppImage via appimagetool..."
  ARCH=x86_64 appimagetool --appimage-extract-and-run "${APPDIR}" "${OUT_DIR}/Warp_IM-${VERSION}-x86_64.AppImage"
  chmod +x "${OUT_DIR}/Warp_IM-${VERSION}-x86_64.AppImage"
fi

# Generate SHA256SUMS
(
  cd "${OUT_DIR}"
  sha256sum *.tar.gz *.deb *.AppImage 2>/dev/null > SHA256SUMS || true
)

echo "✅ Linux packaging complete! Artifacts in ${OUT_DIR}:"
ls -lh "${OUT_DIR}"
