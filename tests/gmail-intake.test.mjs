import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:http';
import { GmailIntakeService } from '../.test-dist/hermes/services/incident-intake/gmail-service.js';
import { GmailApiClient } from '../.test-dist/hermes/services/incident-intake/gmail-client.js';
import { IncidentStore } from '../.test-dist/hermes/services/incident-intake/store.js';
import { extractIocCandidates } from '../.test-dist/hermes/services/incident-intake/ioc-candidates.js';
import { parseGmailReport } from '../.test-dist/hermes/services/incident-intake/gmail-parser.js';

const b64 = s => Buffer.from(s).toString('base64url');
const msg = (id, text = 'Investigasi IP 198.51.100.25 dan domain evil.example.test hash ' + 'a'.repeat(64)) => ({
  id, threadId: 'thread123', internalDate: '1794710121000',
  payload: {
    mimeType: 'multipart/mixed',
    headers: [
      { name: 'Subject', value: 'Laporan serangan SSH' },
      { name: 'From', value: 'Reporter <reporter@company.test>' },
    ],
    parts: [
      { mimeType: 'text/plain', body: { data: b64(text) } },
      { mimeType: 'text/plain', filename: 'evidence.txt', body: { attachmentId: 'attach1', size: 49 } },
    ],
  },
});
const attachment = { data: b64('Koneksi ke https://malware.example.test/c2 dari 203.0.113.8') };
function fakeApi(message = msg('message123')) {
  return {
    list: async limit => ({ messages: [{ id: message.id }].slice(0, limit) }),
    get: async id => { assert.equal(id, message.id); return message; },
    attachment: async () => attachment,
  };
}
async function withStore(callback) {
  const dir = await mkdtemp(join(tmpdir(), 'gmail-intake-test-'));
  try { return await callback(new IncidentStore(dir)); }
  finally { await rm(dir, { recursive: true, force: true }); }
}

test('Gmail pull generates Incident Case with body/document IOC provenance, no severity', async () => withStore(async store => {
  const svc = new GmailIntakeService(store, fakeApi());
  const out = await svc.pull(5);
  assert.equal(out.source, 'gmail');
  assert.equal(out.created, 1);
  assert.equal(out.rejected, 0);
  assert.equal(out.cases[0].status, 'created');
  const c = out.cases[0].incident_case;
  assert.equal(c.source.type, 'email');
  assert.equal(c.source.external_id, 'message123');
  assert.equal(c.classification_status, 'pending');
  assert.equal(c.email.attachments[0].status, 'processed');
  assert.equal(c.ioc_candidates.ips.includes('198.51.100.25'), true);
  assert.equal(c.ioc_candidates.domains.includes('malware.example.test'), true);
  assert.equal(c.ioc_candidates.hashes_sha256.includes('a'.repeat(64)), true);
  assert.equal(c.ioc_candidates.evidence.some(e => e.found_in === 'attachment:evidence.txt'), true);
  assert.equal('severity' in c, false);
  assert.equal(JSON.stringify(c).includes('reporter@company.test'), false);
}));

test('Gmail pull is idempotent and survives store restart', async () => withStore(async store => {
  const first = new GmailIntakeService(store, fakeApi(), 'csirt-local');
  const a = await first.pull();
  const b = await new GmailIntakeService(store, fakeApi(), 'csirt-local').pull();
  assert.equal(a.created, 1);
  assert.equal(b.existing, 1);
  assert.equal(b.cases[0].incident_case.case_id, a.cases[0].incident_case.case_id);
}));

test('Gmail skips executable attachments and never treats From address as IOC', async () => {
  const message = msg('messageAAA', 'Tidak ada indikator dalam body');
  message.payload.parts[1] = { filename: 'payload.exe', mimeType: 'application/octet-stream', body: { attachmentId: 'attach1' } };
  const report = await parseGmailReport(message, fakeApi(message));
  assert.equal(report.attachments[0].status, 'skipped');
  assert.equal(report.attachments[0].reason, 'unsupported-attachment-type');
  const ioc = extractIocCandidates(report.sources);
  assert.equal(ioc.domains.includes('company.test'), false);
});

test('Gmail HTML parser discards scripts and captures visible text only', async () => {
  const message = msg('messageHTML');
  message.payload.parts = [{ mimeType: 'text/html', body: { data: b64('<p>Source 192.0.2.5</p><script>https://evil.hidden.test</script>') } }];
  const report = await parseGmailReport(message, fakeApi(message));
  const ioc = extractIocCandidates(report.sources);
  assert.equal(ioc.ips.includes('192.0.2.5'), true);
  assert.equal(ioc.domains.includes('evil.hidden.test'), false);
});

test('Gmail skips an invalid PDF instead of claiming it was analyzed', async () => {
  const message = msg('messagePDF', 'Laporan terlampir');
  message.payload.parts[1] = { filename: 'incident.pdf', mimeType: 'application/pdf', body: { data: b64('not a pdf') } };
  const report = await parseGmailReport(message, fakeApi(message));
  assert.equal(report.attachments[0].status, 'skipped');
  assert.equal(report.attachments[0].reason, 'invalid-pdf-signature');
});

test('Partial failure does not discard valid Gmail message', async () => withStore(async store => {
  const api = { ...fakeApi(), list: async () => ({ messages: [{id:'message123'}, {id:'messageFAIL'}] }),
    get: async id => { if (id === 'messageFAIL') throw Error('sensitive bearer 123'); return msg('message123'); },
  };
  const out = await new GmailIntakeService(store, api).pull();
  assert.equal(out.created, 1);
  assert.equal(out.rejected, 1);
  assert.equal(out.failures[0], 'message[1]: could-not-ingest');
  assert.equal(JSON.stringify(out).includes('sensitive bearer'), false);
}));

test('Gmail API client searches inbox read-only; fetches message and attachment via mock HTTP', async () => {
  let calls = [];
  const server = createServer((req,res) => {
    calls.push({url:req.url,auth:req.headers.authorization,method:req.method});
    res.setHeader('Content-Type','application/json');
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.endsWith('/messages')) res.end(JSON.stringify({messages:[{id:'m123'}]}));
    else if (url.pathname.endsWith('/messages/m123')) res.end(JSON.stringify({id:'m123',payload:{mimeType:'text/plain',body:{data:b64('hello')}}}));
    else if (url.pathname.endsWith('/attachments/a456')) res.end(JSON.stringify({data:b64('evidence text')}));
    else {res.statusCode=404;res.end('{}');}
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try {
    const port = server.address().port;
    const client = new GmailApiClient({query:'label:CSIRT newer_than:7d',accessToken:'test-token',baseUrl:`http://127.0.0.1:${port}/`});
    assert.equal((await client.list(5)).messages[0].id,'m123');
    assert.equal((await client.get('m123')).id,'m123');
    assert.equal((await client.attachment('m123','a456')).data,b64('evidence text'));
    assert.equal(calls.length,3);
    assert.ok(calls.every(c=>c.method==='GET' && c.auth==='Bearer test-token'));
    assert.ok(calls[0].url.includes('label%3ACSIRT'));
  } finally {await new Promise(resolve=>server.close(resolve));}
});

test('Gmail API refuses arbitrary hosts and missing OAuth/query', () => {
  assert.throws(() => new GmailApiClient({query:'in:inbox',accessToken:'abc',baseUrl:'http://attacker.test/'}), /tidak diizinkan/);
  assert.throws(() => new GmailApiClient({query:'',accessToken:'abc'}), /GMAIL_QUERY/);
  assert.throws(() => new GmailApiClient({query:'label:CSIRT'}), /OAuth/);
});

test('IOC extractor ignores non-IP and separates MD5/SHA256 values', () => {
  const iocs = extractIocCandidates([{name:'body',text:'IP 999.999.999.999 or 192.0.2.33, MD5 '+ 'b'.repeat(32)+' SHA '+ 'a'.repeat(64)}]);
  assert.deepEqual(iocs.ips,['192.0.2.33']);
  assert.deepEqual(iocs.hashes_md5,['b'.repeat(32)]);
  assert.deepEqual(iocs.hashes_sha256,['a'.repeat(64)]);
});

test('Gmail reports pagination token without silently dropping older pages', async () => withStore(async store => {
  const client = {
    ...fakeApi(),
    list: async (limit, pageToken) => {
      assert.equal(limit, 2);
      assert.equal(pageToken, 'second-page');
      return { messages: [{ id: 'message123' }], nextPageToken: 'third-page' };
    },
  };
  const out = await new GmailIntakeService(store, client).pull(2, 'second-page');
  assert.equal(out.created, 1);
  assert.equal(out.has_more, true);
  assert.equal(out.next_page_token, 'third-page');
}));

test('Gmail API error does not leak authorization token', async () => {
  const server = createServer((_req,res) => {res.statusCode=401;res.end(JSON.stringify({detail:'bad-token'}));});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try {
    const port = server.address().port;
    const client = new GmailApiClient({query:'label:CSIRT',accessToken:'supersecret-token',baseUrl:`http://127.0.0.1:${port}/`});
    await assert.rejects(client.list(2), error => error.message.includes('401') && !error.message.includes('supersecret-token') && !error.message.includes('bad-token'));
  } finally {await new Promise(resolve=>server.close(resolve));}
});

test('Gmail client refreshes an OAuth token without network when transport is mocked', async () => {
  let refreshed = 0, apiCalls = 0;
  const fakeFetch = async (url, options) => {
    if (String(url) === 'https://oauth2.googleapis.com/token') {
      refreshed++;
      assert.equal(options.method, 'POST');
      return new Response(JSON.stringify({access_token:'new-token',expires_in:3600}), {status:200});
    }
    apiCalls++;
    assert.equal(options.headers.Authorization, 'Bearer new-token');
    return new Response(JSON.stringify({messages:[{id:'email123'}]}), {status:200});
  };
  const client = new GmailApiClient({query:'label:CSIRT',clientId:'fake-client',clientSecret:'fake-secret',refreshToken:'fake-refresh',fetchImpl:fakeFetch});
  await client.list(1);
  await client.list(1);
  assert.equal(refreshed,1);
  assert.equal(apiCalls,2);
});
