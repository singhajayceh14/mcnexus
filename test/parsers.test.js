'use strict';
const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { loadServer } = require('./helpers');

const { srv, cleanup } = loadServer();
after(cleanup);
const { xmlObj, sqlSources, sqlDepth, patternRe, SECRET_RE, enc, dec, hid, score } = srv;

test('xmlObj strips namespace prefixes, groups repeats, decodes entities and CDATA', () => {
  const o = xmlObj('<?xml version="1.0"?><soap:Envelope xmlns:soap="x"><soap:Body><R><OverallStatus>OK</OverallStatus>'
    + '<Results xsi:type="DataExtension"><Name>A &amp; B</Name><DataExtension><CustomerKey>k1</CustomerKey></DataExtension></Results>'
    + '<Results><Name><![CDATA[<raw>]]></Name><Empty/></Results></R></soap:Body></soap:Envelope>');
  const r = o.Envelope.Body.R;
  assert.equal(r.OverallStatus, 'OK');
  assert.ok(Array.isArray(r.Results));
  assert.equal(r.Results[0].Name, 'A & B');
  assert.equal(r.Results[0].DataExtension.CustomerKey, 'k1');
  assert.equal(r.Results[1].Name, '<raw>');
  assert.equal(r.Results[1].Empty, '');
});

test('xmlObj keeps a single Results as an object (callers wrap with arr())', () => {
  const o = xmlObj('<Body><Results><ID>1</ID></Results></Body>');
  assert.deepEqual(o.Body.Results, { ID: '1' });
});

test('sqlSources finds FROM/JOIN tables in brackets, quotes and ENT. form, ignoring comments and subqueries', () => {
  const sql = `-- FROM Commented_Out
    SELECT a.x FROM [My DE] a
    INNER JOIN ENT.Shared_DE s ON s.k = a.k
    LEFT JOIN "Quoted DE" q ON q.k = a.k
    /* JOIN Block_Comment */
    WHERE a.k IN (SELECT k FROM _Subscribers) AND a.y IN (SELECT y FROM (SELECT y FROM Inner_DE) z)`;
  assert.deepEqual(sqlSources(sql).sort(), ['ENT.Shared_DE', 'Inner_DE', 'My DE', 'Quoted DE', '_Subscribers'].sort());
  assert.deepEqual(sqlSources(''), []);
  assert.deepEqual(sqlSources(null), []);
});

test('sqlDepth counts only nested SELECT parentheses', () => {
  assert.equal(sqlDepth('SELECT a FROM t WHERE x IN (1, 2) AND f(y) = 1'), 0);
  assert.equal(sqlDepth('SELECT a FROM (SELECT a FROM t) x'), 1);
  assert.equal(sqlDepth('SELECT a FROM (SELECT a FROM (SELECT a FROM (SELECT a FROM (SELECT a FROM t) a) b) c) d'), 4);
  assert.equal(sqlDepth('SELECT (SELECT 1) a, (SELECT 2) b'), 1);
});

test('patternRe: last token is permissive, earlier tokens alphanumeric, literals escaped', () => {
  const re = patternRe('DE_<BU>_<NAME>');
  assert.ok(re.test('DE_Retail_Welcome-List_v2'));
  assert.ok(!re.test('DE_Re-tail_Welcome'));
  assert.ok(!re.test('Welcome'));
  assert.ok(!patternRe('Q.<NAME>').test('QxFoo'));
  assert.ok(patternRe('Q.<NAME>').test('Q.Foo'));
});

test('SECRET_RE flags literal credentials only', () => {
  assert.ok(SECRET_RE.test('var client_secret = "abcd1234efgh5678";'));
  assert.ok(SECRET_RE.test("apiKey: 'ZZZZsecretvalue123'"));
  assert.ok(SECRET_RE.test('"password":"correct-horse-battery"'));
  assert.ok(!SECRET_RE.test('var password = "short";'));
  assert.ok(!SECRET_RE.test('var password = Platform.Function.Lookup("Keys","v","k","pw");'));
});

test('enc/dec round-trip with a fresh IV each time; tampering is rejected', () => {
  const a = enc('s3cret'), b = enc('s3cret');
  assert.notEqual(a, b);
  assert.equal(dec(a), 's3cret');
  const [iv, tag, d] = a.split('.');
  const flipped = Buffer.from(d, 'base64'); flipped[0] ^= 1;
  assert.throws(() => dec([iv, tag, flipped.toString('base64')].join('.')));
});

test('hid is the first 6 hex chars of sha1, upper-cased (finding ID scheme)', () => {
  const want = crypto.createHash('sha1').update('SQL-001|SQL:1:q').digest('hex').slice(0, 6).toUpperCase();
  assert.equal(hid('SQL-001|SQL:1:q'), want);
});

test('score follows 100 - 100P/(P + 10 + 1.5N)', () => {
  assert.equal(score(0, 50), 100);
  assert.equal(score(10, 0), 50);
  assert.equal(score(14, 4), Math.round(100 - 1400 / (14 + 10 + 6)));
});
