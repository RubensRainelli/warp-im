#!/usr/bin/env bash
# Personal and Educational Free License (PEF License / PEFL)
# Version 1.0 - 2026-05-26
# Copyright (c) 2026 Rubens Rainelli (rubens@rainelli.it)
#
# Assembles, aligns, and signs the installable Android NativeActivity APK
# (`warp-im-<version>-android-arm64-v8a.apk`) from `libwarp_app.so`.

set -euo pipefail

VER="${1:-0.1.0}"
SO_PATH="${2:-target/aarch64-linux-android/release/libwarp_app.so}"

if [[ ! -f "${SO_PATH}" ]]; then
  echo "ERROR: Native library not found at ${SO_PATH}" >&2
  exit 1
fi

ANDROID_SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/usr/local/lib/android/sdk}}"

find_sdk_tool() {
  local tool_name="$1"
  if [[ -d "${ANDROID_SDK}/build-tools" ]]; then
    find "${ANDROID_SDK}/build-tools" -name "${tool_name}" -type f 2>/dev/null | sort -V | tail -n 1 || true
  fi
}

find_android_jar() {
  if [[ -d "${ANDROID_SDK}/platforms" ]]; then
    find "${ANDROID_SDK}/platforms" -name "android.jar" -type f 2>/dev/null | sort -V | tail -n 1 || true
  fi
}

AAPT="$(find_sdk_tool aapt)"
ZIPALIGN="$(find_sdk_tool zipalign)"
APKSIGNER="$(find_sdk_tool apksigner)"
ANDROID_JAR="$(find_android_jar)"

# Ensure Android SDK platform & build-tools exist on GitHub Actions runner
if [[ -z "${AAPT}" || -z "${ZIPALIGN}" || -z "${APKSIGNER}" || -z "${ANDROID_JAR}" ]]; then
  echo "Installing Android SDK platform-34 & build-tools;34.0.0 via sdkmanager..."
  SDKMANAGER="$(find "${ANDROID_SDK}" -name sdkmanager -type f 2>/dev/null | head -n 1 || true)"
  if [[ -n "${SDKMANAGER}" ]]; then
    yes | "${SDKMANAGER}" --licenses >/dev/null 2>&1 || true
    "${SDKMANAGER}" "platforms;android-34" "build-tools;34.0.0"
  fi
  AAPT="$(find_sdk_tool aapt)"
  ZIPALIGN="$(find_sdk_tool zipalign)"
  APKSIGNER="$(find_sdk_tool apksigner)"
  ANDROID_JAR="$(find_android_jar)"
fi

echo "Using Android SDK tools:"
echo "  AAPT        = ${AAPT}"
echo "  ZIPALIGN    = ${ZIPALIGN}"
echo "  APKSIGNER   = ${APKSIGNER}"
echo "  ANDROID_JAR = ${ANDROID_JAR}"

WORK_DIR="dist/android/apk-work"
OUT_DIR="dist/android/out"
rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}/res/values" "${WORK_DIR}/assets" "${WORK_DIR}/lib/arm64-v8a" "${OUT_DIR}"

# 1. Prepare AndroidManifest.xml and resources
sed "s/android:versionName=\"[^\"]*\"/android:versionName=\"${VER}\"/g" \
  packaging/android/AndroidManifest.xml > "${WORK_DIR}/AndroidManifest.xml"

cat > "${WORK_DIR}/res/values/strings.xml" << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Warp IM</string>
</resources>
EOF

# 2. Bundle PEFL v1.0 license files and all SuperTheme / Palette TOMLs into APK assets
cp LICENSE LICENSE.it NOTICE.md "${WORK_DIR}/assets/"
mkdir -p "${WORK_DIR}/assets/themes/superthemes" "${WORK_DIR}/assets/themes/palettes"
cp -r crates/warp-app/themes/superthemes/* "${WORK_DIR}/assets/themes/superthemes/" 2>/dev/null || true
cp -r crates/warp-app/themes/palettes/* "${WORK_DIR}/assets/themes/palettes/" 2>/dev/null || true
cp -r themes/superthemes/* "${WORK_DIR}/assets/themes/superthemes/" 2>/dev/null || true
cp -r themes/palettes/* "${WORK_DIR}/assets/themes/palettes/" 2>/dev/null || true

# 3. Copy compiled Rust arm64-v8a shared library (`libwarp_app.so`)
cp "${SO_PATH}" "${WORK_DIR}/lib/arm64-v8a/libwarp_app.so"

# 4. Package resources and AndroidManifest.xml with aapt
UNALIGNED_APK="${WORK_DIR}/warp-im-unaligned.apk"
ALIGNED_APK="${WORK_DIR}/warp-im-aligned.apk"
FINAL_APK="${OUT_DIR}/warp-im-${VER}-android-arm64-v8a.apk"

"${AAPT}" package -f \
  -M "${WORK_DIR}/AndroidManifest.xml" \
  -S "${WORK_DIR}/res" \
  -A "${WORK_DIR}/assets" \
  -I "${ANDROID_JAR}" \
  -F "${UNALIGNED_APK}"

# 5. Add native library `lib/arm64-v8a/libwarp_app.so` into the APK archive
(
  cd "${WORK_DIR}"
  zip -u -0 "warp-im-unaligned.apk" "lib/arm64-v8a/libwarp_app.so"
)

# 6. Align APK on 4-byte / page boundaries with zipalign
"${ZIPALIGN}" -p -f 4 "${UNALIGNED_APK}" "${ALIGNED_APK}"

# 7. Resolve signing Keystore (Private `.private/android/`, GitHub Secret, or ephemeral fallback)
KS_FILE="${WORK_DIR}/signing.keystore"
KEY_ALIAS="${ANDROID_KEY_ALIAS:-warp-im-release}"
KS_PASS="${ANDROID_KEYSTORE_PASSWORD:-}"
KEY_PASS="${ANDROID_KEY_PASSWORD:-${KS_PASS}}"

if [[ -n "${ANDROID_KEYSTORE_BASE64:-}" && -n "${KS_PASS}" ]]; then
  echo "Signing APK with GitHub Actions repository secret ANDROID_KEYSTORE_BASE64..."
  printf "%s" "${ANDROID_KEYSTORE_BASE64}" | base64 -d > "${KS_FILE}"
elif [[ -f ".private/android/warp-im-release.keystore" && -f ".private/android/keystore_credentials.toml" ]]; then
  echo "Signing APK with local private keystore (.private/android/warp-im-release.keystore)..."
  cp ".private/android/warp-im-release.keystore" "${KS_FILE}"
  KS_PASS="$(grep '^keystore_password' .private/android/keystore_credentials.toml | cut -d'"' -f2)"
  KEY_PASS="$(grep '^key_password' .private/android/keystore_credentials.toml | cut -d'"' -f2)"
  KEY_ALIAS="$(grep '^key_alias' .private/android/keystore_credentials.toml | cut -d'"' -f2)"
else
  echo "Signing APK with auto-generated PKCS12 keystore..."
  KS_PASS="warpim-pefl-2026"
  KEY_PASS="warpim-pefl-2026"
  keytool -genkeypair -v \
    -keystore "${KS_FILE}" \
    -storetype PKCS12 \
    -alias "${KEY_ALIAS}" \
    -keyalg RSA \
    -keysize 4096 \
    -validity 10000 \
    -storepass "${KS_PASS}" \
    -keypass "${KEY_PASS}" \
    -dname "CN=Warp IM, OU=PEFL v1.0, O=Rubens Rainelli, L=Italia, ST=IT, C=IT"
fi

# 8. Sign APK (v1 + v2 + v3 schemes) and verify signature
"${APKSIGNER}" sign \
  --ks "${KS_FILE}" \
  --ks-key-alias "${KEY_ALIAS}" \
  --ks-pass "pass:${KS_PASS}" \
  --key-pass "pass:${KEY_PASS}" \
  --v1-signing-enabled true \
  --v2-signing-enabled true \
  --v3-signing-enabled true \
  --out "${FINAL_APK}" \
  "${ALIGNED_APK}"

rm -f "${KS_FILE}" "${FINAL_APK}.idsig"
"${APKSIGNER}" verify --verbose "${FINAL_APK}"

sha256sum "${FINAL_APK}" > "${FINAL_APK}.sha256"
echo "Successfully built and signed Android APK: ${FINAL_APK}"
ls -lh "${OUT_DIR}"
