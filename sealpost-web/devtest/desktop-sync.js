const R = '/home/claude/sealpost/src/main/';
const { Store } = require(R + 'store'), { PgpEngine } = require(R + 'pgp'), { ContactStore } = require(R + 'contacts'), { SyncService } = require(R + 'sync');
(async () => {
  const dir = process.argv[2];
  const store = new Store(dir), pgp = new PgpEngine(dir); await pgp.load(); const contacts = new ContactStore(dir);
  const s = new SyncService({ dataDir: dir, store, pgp, contacts });
  const r = await s.sync();
  console.log(JSON.stringify(r.result), 'contacts:', contacts.list.map(c => c.emails[0] + (c.keyFp ? '🔑' : '')).join(', '), '| synced passphrases:', pgp.syncedFingerprints().map(f => f.slice(-8)), '| keys:', [...pgp.publicKeys.keys()].map(f => f.slice(-8)));
})();
