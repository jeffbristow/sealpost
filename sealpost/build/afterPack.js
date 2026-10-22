/* =====================================================================
 * Sealpost — build/afterPack.js
 * electron-builder hook: stamps Sealpost's icon and version details into
 * Sealpost.exe. Uses pure-JavaScript "resedit", so building the Windows
 * installer works from Windows, Mac or Linux (no Wine needed).
 * ===================================================================== */
const fs = require('fs');
const path = require('path');

exports.default = async function afterPack(context) {
  if (context.electronPlatformName !== 'win32') return;
  const ResEdit = await import('resedit');
  const { NtExecutable, NtExecutableResource, Resource, Data } = ResEdit;

  const exe = path.join(context.appOutDir, context.packager.appInfo.productFilename + '.exe');
  const version = context.packager.appInfo.version;
  const exeData = NtExecutable.from(fs.readFileSync(exe), { ignoreCert: true });
  const res = NtExecutableResource.from(exeData);

  // --- icon
  const iconFile = Data.IconFile.from(fs.readFileSync(path.join(__dirname, 'icon.ico')));
  Resource.IconGroupEntry.replaceIconsForResource(
    res.entries, 1, 1033, iconFile.icons.map(i => i.data)
  );

  // --- version info shown in File Properties / Task Manager
  const vi = Resource.VersionInfo.fromEntries(res.entries)[0] || Resource.VersionInfo.createEmpty();
  const [ma, mi, pa] = version.split('.').map(Number);
  vi.setFileVersion(ma, mi, pa, 0, 1033);
  vi.setProductVersion(ma, mi, pa, 0, 1033);
  vi.setStringValues({ lang: 1033, codepage: 1200 }, {
    FileDescription: 'Sealpost Mail',
    ProductName: 'Sealpost',
    CompanyName: 'Sealpost',
    LegalCopyright: 'Sealpost',
    OriginalFilename: 'Sealpost.exe',
    InternalName: 'Sealpost'
  });
  vi.outputToResourceEntries(res.entries);

  res.outputResource(exeData);
  fs.writeFileSync(exe, Buffer.from(exeData.generate()));
  console.log('  • afterPack: icon + version info written to', path.basename(exe));
};
