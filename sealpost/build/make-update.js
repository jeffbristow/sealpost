/* =====================================================================
 * Sealpost — build/make-update.js      (run with: npm run update-file)
 * ---------------------------------------------------------------------
 * Builds an update package instead of a full installer:
 *   dist/update/Sealpost-<ver>.sealpost   the app code (load it with
 *                                         Settings → Install update file…)
 *   dist/update/Sealpost-Update-<ver>.zip that file + Install-Update.bat/.ps1
 *                                         for installs without the button
 *                                         (version 1.0.0)
 * ===================================================================== */
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const version = require('../package.json').version;
const out = path.join(root, 'dist', 'update');

console.log('Packing app code for', version, '...');
execSync('npx electron-builder --win --x64 --dir --publish never', { cwd: root, stdio: 'inherit' });

const asar = path.join(root, 'dist', 'win-unpacked', 'resources', 'app.asar');
fs.mkdirSync(out, { recursive: true });
const updFile = path.join(out, `Sealpost-${version}.sealpost`);
fs.copyFileSync(asar, updFile);
fs.copyFileSync(path.join(__dirname, 'Install-Update.bat'), path.join(out, 'Install-Update.bat'));
fs.copyFileSync(path.join(__dirname, 'Install-Update.ps1'), path.join(out, 'Install-Update.ps1'));

const zip = path.join(out, `Sealpost-Update-${version}.zip`);
try { fs.unlinkSync(zip); } catch { /* none */ }
if (process.platform === 'win32') {
  execSync(`powershell -NoProfile -Command "Compress-Archive -Path '${updFile}','${path.join(out, 'Install-Update.bat')}','${path.join(out, 'Install-Update.ps1')}' -DestinationPath '${zip}'"`);
} else {
  execSync(`zip -j -9 "${zip}" "${updFile}" "${path.join(out, 'Install-Update.bat')}" "${path.join(out, 'Install-Update.ps1')}"`);
}
console.log('\nUpdate ready:\n ', updFile, '\n ', zip);
