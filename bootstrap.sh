#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
APP="$ROOT/app"
CORE="$ROOT/packages/secure_dns_core"

echo "==> 检查 Flutter"
if ! command -v flutter >/dev/null 2>&1; then
  echo "未找到 flutter，请先安装 Flutter 3.24+ 并加入 PATH。" >&2
  exit 1
fi
flutter --version

echo "==> 检查 Dart（用于核心包测试）"
if ! command -v dart >/dev/null 2>&1; then
  echo "未找到独立 dart，Flutter 自带的 dart 可用于核心包测试。" >&2
fi

echo "==> 生成 Android / Windows 平台目录"
cd "$APP"
flutter create --platforms=android,windows --project-name cf_browser_app .

echo "==> 安装应用依赖"
flutter pub get

echo "==> 安装并验证核心包"
cd "$CORE"
dart pub get || flutter pub get
dart analyze
dart test

echo "完成。运行方式："
echo "  cd '$APP' && flutter run -d windows"
echo "  cd '$APP' && flutter run -d <android-device-id>"
