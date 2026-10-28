/* =====================================================================
 * Sealpost Web — update.js  (Server updates, added 1.10.0)
 * ---------------------------------------------------------------------
 * Tells you when a newer Sealpost Server is out and installs it with one
 * click (update.php on your server does the work: Sealpost-signed
 * packages only, config.php and your vault are never touched, Undo puts
 * the previous version back).
 *
 * Sections:
 *   1. Talking to update.php
 *   2. The notice (sidebar card + a message once per sign-in)
 *   3. Settings → Server updates
 *   4. Install / undo
 * ===================================================================== */
import { $, esc, show, toast, dialog, confirmBox, loading } from './ui.js?v=1.11.2';

export function initUpdates(ctx) {
  let st = null;            // the last answer from update.php
  let told = false;         // the "new version" message was shown this sign-in

  /* =================================================================
   * 1. TALKING TO UPDATE.PHP
   * ================================================================= */
  async function ask(action) {
    st = await ctx.vault.post('update.php', action, {});
    render();
    return st;
  }

  /* =================================================================
   * 2. THE NOTICE
   * ================================================================= */
  function renderNote() {
    const box = $('#updateNote');
    const u = st && st.update;
    show(box, !!u);
    if (!u) return;
    box.innerHTML = `<div><b>Update available</b><br><span class="small">Sealpost Server ${esc(u.version)}</span></div>
      <button class="btn small primary" type="button">Update now</button>`;
    box.querySelector('button').onclick = install;
  }

  /** After sign-in: look for an update quietly (the server asks GitHub at most every 12 hours). */
  async function start() {
    try { await ask('status'); } catch { return; }    // an older server without update.php: nothing to show
    if (st.update && !told) {
      told = true;
      toast(`Sealpost Server ${st.update.version} is available — Settings → Server updates, or "Update now" in the menu.`);
    }
  }

  /* =================================================================
   * 3. SETTINGS → SERVER UPDATES
   * ================================================================= */
  function renderPanel() {
    const box = $('#stUpdate');
    if (!box) return;
    if (!st) {
      box.innerHTML = '<p class="muted small">Checking…</p>';
      ask('status').catch(e => { box.innerHTML = `<p class="small">Couldn't ask the server about updates: ${esc(e.message)}</p>`; });
      return;
    }
    const when = st.checked ? new Date(st.checked * 1000).toLocaleString() : 'never';
    let html = `<p class="small">This server: <b>Sealpost Server ${esc(st.current)}</b><br><span class="muted">Last checked: ${esc(when)}</span></p>`;
    if (st.update) {
      html += `<p class="small"><b>Version ${esc(st.update.version)} is available</b>${st.update.size ? ' (' + esc(st.update.size) + ')' : ''}.${st.update.note ? '<br>' + esc(st.update.note) : ''}</p>`;
    } else if (st.error) {
      html += `<p class="small">Couldn't check for updates: ${esc(st.error)}</p>`;
    } else if (st.latest) {
      html += '<p class="small muted">This is the newest version.</p>';
    }
    if (st.update && st.blockers && st.blockers.length) {
      html += `<p class="small">This server can't update itself: ${esc(st.blockers.join('; '))}. Upload the new version by hand instead (keep your config.php).</p>`;
    }
    html += `<div class="row-btns">
      <button id="upCheck" class="btn" type="button">Check now</button>
      ${st.update ? '<button id="upInstall" class="btn primary" type="button">Update now</button>' : ''}
      ${st.undo ? `<button id="upUndo" class="btn" type="button">Undo (back to ${esc(st.undo)})</button>` : ''}
    </div>
    <p class="muted small">Updates come from Sealpost's GitHub page and are installed only if they carry Sealpost's signature. Your config.php and your vault are never changed.</p>`;
    box.innerHTML = html;
    $('#upCheck').onclick = async () => {
      try { await ask('check'); toast(st.update ? `Version ${st.update.version} is available.` : st.error ? 'Couldn\'t check: ' + st.error : 'This is the newest version.', st.error && !st.update ? 'err' : ''); }
      catch (e) { toast(e.message, 'err'); }
    };
    if ($('#upInstall')) $('#upInstall').onclick = install;
    if ($('#upUndo')) $('#upUndo').onclick = undo;
  }

  function render() { renderNote(); renderPanel(); }

  /* =================================================================
   * 4. INSTALL / UNDO
   * ================================================================= */
  async function install() {
    if (!st || !st.update) return;
    if (!(await confirmBox('Update Sealpost Server',
      `Update this server from ${st.current} to ${st.update.version}? It takes a few seconds. Your settings (config.php), your vault and your mail are not changed, and you can undo it in Settings.`,
      'Update now'))) return;
    await run('install', 'Updating Sealpost Server…');
  }

  async function undo() {
    if (!st || !st.undo) return;
    if (!(await confirmBox('Undo the update', `Go back to Sealpost Server ${st.undo}?`, 'Go back'))) return;
    await run('undo', 'Putting the previous version back…');
  }

  /** Runs install / undo, then reloads so this page uses the new files too. */
  async function run(action, text) {
    loading(text);
    let r;
    try { r = await ask(action); }
    catch (e) {
      loading(null);
      ask('status').catch(() => {});
      await dialog({ title: action === 'install' ? 'Update not installed' : 'Undo failed', html: `<p>${esc(e.message)}</p>`, hideCancel: true });
      return;
    }
    loading(null);
    await dialog({ title: 'Done', html: `<p>${esc(r.message)}</p><p class="muted small">Sealpost Web will reload now to use the new version.</p>`, okText: 'Reload', hideCancel: true });
    location.reload();
  }

  return { start, renderPanel };
}
