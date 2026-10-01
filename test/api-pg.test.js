'use strict';
const { test } = require('node:test');
const { PgStore } = require('../server/store-pg');
const { pgliteAdapter, pgDump, SCHEMA } = require('./helpers');

let has = true; try { require.resolve('@electric-sql/pglite'); } catch { has = false; }
if (!has) test('API on PgStore (PGlite)', { skip: 'PGlite not installed (npm install)' }, () => { });
else require('./api-suite')('API on PgStore (PGlite)', async () => {
  const a = await pgliteAdapter(); await a.exec(SCHEMA());
  return { store: new PgStore(a), raw: () => pgDump(a) };
});
