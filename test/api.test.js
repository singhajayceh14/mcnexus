'use strict';
const fs = require('fs'), os = require('os'), path = require('path');
const { JsonStore } = require('../server/store');
const { jsonDump } = require('./helpers');

require('./api-suite')('API on JsonStore', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcnexus-api-'));
  return { store: new JsonStore(dir), reopen: () => new JsonStore(dir), raw: async () => jsonDump(dir), cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
});
