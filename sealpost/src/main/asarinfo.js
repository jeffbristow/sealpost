/* =====================================================================
 * Sealpost — asarinfo.js   (added 1.0.3)
 * ---------------------------------------------------------------------
 * Reads package.json out of an update file (.asar / .sealpost) WITHOUT
 * using Electron's built-in asar support.
 *
 * Why: when Electron looks inside an .asar it keeps the file open for the
 * rest of the session. On Windows an open file cannot be renamed or
 * deleted, which caused "EBUSY: resource busy or locked" when installing
 * an update in 1.0.1/1.0.2. Here we open the file ourselves, read the
 * few bytes we need, and close it immediately.
 *
 * asar layout: [4 bytes][4 bytes header size][4][4 bytes JSON length]
 *              [JSON directory header] [file data...]
 * ===================================================================== */

let fs;
try { fs = require('original-fs'); } catch { fs = require('fs'); } // original-fs = no asar magic

function readPackageJson(file) {
  const fd = fs.openSync(file, 'r');
  try {
    const head = Buffer.alloc(16);
    fs.readSync(fd, head, 0, 16, 0);
    const headerSize = head.readUInt32LE(4);   // size of the header pickle
    const jsonLen = head.readUInt32LE(12);     // length of the JSON string
    if (jsonLen <= 0 || jsonLen > 50 * 1024 * 1024) throw new Error('not an asar archive');

    const jsonBuf = Buffer.alloc(jsonLen);
    fs.readSync(fd, jsonBuf, 0, jsonLen, 16);
    const header = JSON.parse(jsonBuf.toString('utf8'));

    const entry = header.files && header.files['package.json'];
    if (!entry || entry.offset === undefined) throw new Error('package.json missing');
    const dataStart = 8 + headerSize;
    const buf = Buffer.alloc(entry.size);
    fs.readSync(fd, buf, 0, entry.size, dataStart + Number(entry.offset));
    const pkg = JSON.parse(buf.toString('utf8'));

    // must also contain the app's main code
    const main = header.files.src && header.files.src.files && header.files.src.files.main;
    pkg.__hasMain = !!(main && main.files && main.files['main.js']);
    return pkg;
  } finally {
    fs.closeSync(fd); // released immediately — file can be renamed/deleted
  }
}

module.exports = { readPackageJson, fs };
