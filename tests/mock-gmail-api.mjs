/** Local mock Gmail API for MCP Inspector demo; deliberately binds to localhost only. */
import { createServer } from 'node:http';

const token = 'local-mock-token';
const encode = value => Buffer.from(value, 'utf8').toString('base64url');
const message = {
  id: 'mock-csirt-001', threadId: 'mock-thread-001', internalDate: '1794710121000',
  payload: {
    mimeType: 'multipart/mixed',
    headers: [
      { name: 'Subject', value: 'Laporan akses SSH mencurigakan' },
      { name: 'From', value: 'CSIRT reporter <analyst@company.test>' },
    ],
    parts: [
      { mimeType: 'text/plain', body: {
        data: encode('Terdeteksi percobaan login SSH dari 198.51.100.25 dan URL https://login.evil.example.test/validate'),
      } },
      { filename: 'evidence.txt', mimeType: 'text/plain', body: {
        attachmentId: 'mock-evidence-001', size: 100,
      } },
    ],
  },
};
const server = createServer((req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  if (req.headers.authorization !== `Bearer ${token}`) {
    res.writeHead(401); res.end(JSON.stringify({ error: 'Unauthorized' })); return;
  }
  const url = new URL(req.url, 'http://127.0.0.1');
  if (req.method !== 'GET') {
    res.writeHead(405); res.end(JSON.stringify({ error: 'Method not allowed' })); return;
  }
  if (url.pathname === '/gmail/v1/users/me/messages') {
    res.end(JSON.stringify({ messages: [{ id: message.id }], resultSizeEstimate: 1 })); return;
  }
  if (url.pathname === `/gmail/v1/users/me/messages/${message.id}`) {
    res.end(JSON.stringify(message)); return;
  }
  if (url.pathname === `/gmail/v1/users/me/messages/${message.id}/attachments/mock-evidence-001`) {
    res.end(JSON.stringify({ data: encode('Indikator tambahan: 203.0.113.77, malware.bad.example.test, hash '+ 'b'.repeat(32)) })); return;
  }
  res.writeHead(404); res.end(JSON.stringify({ error: 'Not found' }));
});
server.listen(4599, '127.0.0.1', () => {
  console.log('Mock Gmail API ready: http://127.0.0.1:4599/');
  console.log('Local demonstration only; no real Gmail mailbox is accessed');
});
