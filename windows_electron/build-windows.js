'use strict';

const fs = require('fs');
const path = require('path');
const packager = require('@electron/packager');

async function main() {
  const out = process.env.CF_BROWSER_OUT_DIR ||
    path.resolve(__dirname, '..', 'dist', 'windows');
  const zipDir = process.env.ELECTRON_ZIP_DIR ||
    path.resolve(__dirname, '..', '..', '.tools', 'electron-dist');
  await packager({
    dir: __dirname,
    platform: 'win32',
    arch: 'x64',
    out,
    electronZipDir: fs.existsSync(zipDir) ? zipDir : undefined,
    overwrite: true,
    name: 'BigJump',
    executableName: 'BigJump',
    appVersion: process.env.BIGJUMP_VERSION || '1.0.0',
    icon: path.join(__dirname, 'assets', 'icon.ico'),
    win32metadata: {
      CompanyName: 'BigJump',
      FileDescription: 'BigJump — Cloudflare IP 优选与 DNS Security 浏览器',
      ProductName: 'BigJump',
    },
    ignore: [
      /node_modules[\\/]@electron[\\/]packager/,
      /node_modules[\\/]electron[\\/]/,
      /build-windows\.js$/,
    ],
  });
  console.log('Windows EXE 输出目录：' + out);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
