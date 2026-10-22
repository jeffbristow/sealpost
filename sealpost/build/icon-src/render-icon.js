/* Renders sealpost-icon.svg to PNG at any size using the bundled Chromium (Playwright).
 * usage: node render-icon.js <svg> <out.png> <size> */
const { chromium } = require('playwright');
const fs = require('fs');
(async () => {
  const [svgPath, out, size] = process.argv.slice(2);
  const svg = fs.readFileSync(svgPath, 'utf8');
  const b = await chromium.launch({ executablePath: process.env.CHROME_PATH || undefined });
  const p = await b.newPage({ viewport: { width: +size, height: +size } });
  await p.setContent(`<html><body style="margin:0;background:transparent">${svg.replace('<svg ', `<svg style="display:block;width:${size}px;height:${size}px" `)}</body></html>`);
  await p.screenshot({ path: out, omitBackground: true, clip: { x: 0, y: 0, width: +size, height: +size } });
  await b.close();
})();
