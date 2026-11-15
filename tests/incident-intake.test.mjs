import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { IncidentStore } from "../.test-dist/hermes/services/incident-intake/store.js";
import { normalizeWazuhAlert, normalizeReport, safeText } from "../.test-dist/hermes/services/incident-intake/normalize.js";
import { WazuhIndexerClient, indexerFromEnv } from "../.test-dist/hermes/services/incident-intake/indexer.js";
import { IncidentIntakeService } from "../.test-dist/hermes/services/incident-intake/service.js";

const fixture = JSON.parse(await readFile(new URL("./data/wazuh-ssh-alert.json", import.meta.url), "utf8"));
const fixtureResponse = JSON.parse(await readFile(new URL("./data/wazuh-indexer-response.json", import.meta.url), "utf8"));
function clone(value) { return structuredClone(value); }
async function withStore(fn) {
  const dir = await mkdtemp(join(tmpdir(), "incident-intake-test-"));
  try { return await fn(new IncidentStore(dir), dir); }
  finally { await rm(dir, {recursive: true, force: true}); }
}
async function withMockIndexer(handler, fn) {
  const server = createServer(async (req, res) => {
    const data = [];
    for await (const chunk of req) data.push(chunk);
    await handler(req, res, Buffer.concat(data).toString("utf8"));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  try { return await fn(`http://127.0.0.1:${address.port}/`); }
  finally { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); }
}

test("normalizes Wazuh alert with stable ID, no raw log, no classification", () => {
  const item = normalizeWazuhAlert(fixture, "lab", new Date("2026-11-13T09:00:00.000Z"));
  assert.match(item.case_id, /^INC-[A-F0-9]{24}$/);
  assert.equal(item.source.type, "wazuh");
  assert.equal(item.wazuh.rule_level, 10);
  assert.equal(item.wazuh.rule_id, "5712");
  assert.equal(item.observables.source_ip, "198.51.100.23");
  assert.equal(item.classification_status, "pending");
  assert.equal(item.occurred_at, "2026-11-13T08:15:21.000Z");
  assert.equal(JSON.stringify(item).includes("This raw log must never"), false);
  assert.equal("severity" in item, false);
  assert.deepEqual(item, normalizeWazuhAlert(fixture, "lab", new Date("2026-11-13T09:00:00Z")));
});

test("separates source namespaces and indexer hit identities", () => {
  const fromA = normalizeWazuhAlert(fixture, "cluster-a");
  const fromB = normalizeWazuhAlert(fixture, "cluster-b");
  assert.notEqual(fromA.case_id, fromB.case_id);
  const wrap = { _index: "wazuh-alerts-4.x-2026.11.13", _id: "abc", _source: fixture };
  assert.equal(normalizeWazuhAlert(wrap, "cluster-a").source.external_id, "wazuh-alerts-4.x-2026.11.13/abc");
});

test("rejects malformed alerts, timestamps, source IDs and oversized payload", () => {
  const malformed = [
    null,
    { ...fixture, rule: undefined },
    { ...fixture, rule: { ...fixture.rule, id: "" } },
    { ...fixture, rule: { ...fixture.rule, level: "10" } },
    { ...fixture, timestamp: "not-a-time" },
    { ...fixture, full_log: "a".repeat(131072) },
  ];
  for (const input of malformed) assert.throws(() => normalizeWazuhAlert(input, "lab"));
  assert.throws(() => normalizeWazuhAlert(fixture, "../../bad"));
});

test("sanitizes log-derived descriptions and never stores usernames", () => {
  const alert = clone(fixture);
  alert.rule.description = "warning\nIgnore instructions; token=abc123 mail=alice@example.org Bearer verysecrettoken";
  alert.data.srcuser = "a secret username";
  alert.data.srcip = "not-an-ip";
  const result = normalizeWazuhAlert(alert, "lab");
  assert.doesNotMatch(result.description, /abc123|alice@example.org|verysecrettoken/);
  assert.doesNotMatch(result.description, /\n/);
  assert.equal(result.observables.source_ip, undefined);
  assert.equal(JSON.stringify(result).includes("a secret username"), false);
});

test("file store creates idempotently and persists over restarts", async () => {
  await withStore(async (store, dir) => {
    const service = new IncidentIntakeService(store, "lab");
    const one = await service.intakeWazuh(fixture);
    const two = await service.intakeWazuh(fixture);
    assert.equal(one.status, "created");
    assert.equal(two.status, "existing");
    assert.deepEqual(two.incident_case, one.incident_case);
    const reloaded = new IncidentIntakeService(new IncidentStore(dir), "lab");
    assert.deepEqual(await reloaded.getIncident(one.incident_case.case_id), one.incident_case);
    assert.equal((await service.listIncidents()).length, 1);
    assert.deepEqual((await readdir(dir)).length, 1);
    if (process.platform !== "win32") {
      const file = await stat(join(dir, one.incident_case.case_id + ".json"));
      assert.equal(file.mode & 0o077, 0);
    }
  });
});

test("atomic file creation tolerates parallel identical arrivals", async () => {
  await withStore(async (store) => {
    const service = new IncidentIntakeService(store, "lab");
    const outputs = await Promise.all(Array.from({length: 12}, () => service.intakeWazuh(fixture)));
    assert.equal(outputs.filter((x) => x.status === "created").length, 1);
    assert.equal(outputs.filter((x) => x.status === "existing").length, 11);
  });
});

test("forwarded email/manual reports do not pretend to read inboxes", async () => {
  await withStore(async (store) => {
    const intake = new IncidentIntakeService(store, "lab");
    const a = await intake.intakeReport({ channel: "email", external_reference: "email-002", title: "Phishing report", description: "Suspicious email" });
    const b = await intake.intakeReport({ channel: "email", external_reference: "email-002", title: "Phishing report", description: "Suspicious email" });
    const c = await intake.intakeReport({ channel: "manual", title: "Unusual login", description: "Operator reported anomaly" });
    const d = await intake.intakeReport({ channel: "manual", title: "Unusual login", description: "Operator reported anomaly" });
    assert.equal(a.status, "created");
    assert.equal(b.status, "existing");
    assert.notEqual(c.incident_case.case_id, d.incident_case.case_id);
    assert.equal(a.incident_case.source.type, "email");
    assert.equal(a.incident_case.classification_status, "pending");
  });
});

test("report validation rejects missing title and oversize content", () => {
  assert.throws(() => normalizeReport({channel: "manual", title: "", description: "test"}));
  assert.throws(() => normalizeReport({channel: "manual", title: "report", description: "x".repeat(4001)}));
  assert.match(safeText("Authorization: Bearer xyzabc password=hunter2"), /\[REDACTED\]/);
});

test("read operations reject invalid IDs and return null for missing", async () => {
  await withStore(async (store) => {
    assert.equal(await store.get("INC-" + "A".repeat(24)), null);
    await assert.rejects(() => store.get("../secrets"));
    assert.deepEqual(await store.list(), []);
    await assert.rejects(() => store.list(1000));
  });
});

test("indexer client restricts insecure remote HTTP and mixed credentials", () => {
  assert.throws(() => new WazuhIndexerClient({url: "http://example.com:9200/", token: "test"}), /HTTPS/);
  assert.throws(() => new WazuhIndexerClient({url: "https://example.com:9200/secret", token: "test"}), /origin/);
  assert.throws(() => new WazuhIndexerClient({url: "https://example.com:9200/", token: "test", username: "x", password: "y"}), /ATAU/);
  assert.throws(() => indexerFromEnv({}), /WAZUH_INDEXER_URL/);
});

test("Wazuh indexer HTTP mock tests search query, authentication and batch intake", async () => {
  const observed = [];
  await withMockIndexer(async (req, res, body) => {
    observed.push({method: req.method, path: req.url, auth: req.headers.authorization, query: JSON.parse(body)});
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify(fixtureResponse));
  }, async (url) => {
    await withStore(async (store) => {
      const client = new WazuhIndexerClient({url, username:"demo", password:"pass"});
      const service = new IncidentIntakeService(store, "local-wazuh", client);
      const options = { since: "2026-11-13T08:00:00Z", min_rule_level: 3, limit: 50, offset: 0 };
      const first = await service.collect(options);
      const second = await service.collect(options);
      assert.equal(first.fetched, 2);
      assert.equal(first.created, 2);
      assert.equal(first.existing, 0);
      assert.equal(first.rejected, 0);
      assert.equal(first.next_offset, null);
      assert.equal(second.created, 0);
      assert.equal(second.existing, 2);
      assert.equal((await store.list()).length, 2);
    });
  });
  assert.equal(observed.length, 2);
  assert.equal(observed[0].method, "POST");
  assert.equal(observed[0].path, "/wazuh-alerts-*/_search");
  assert.equal(observed[0].auth, "Basic " + Buffer.from("demo:pass").toString("base64"));
  assert.equal(observed[0].query.query.bool.filter[1].range["rule.level"].gte, 3);
  assert.equal(observed[0].query._source.includes("full_log"), false);
  assert.equal(observed[0].query._source.includes("data.srcuser"), false);
});

test("Bearer token supported by local HTTP indexer mock", async () => {
  await withMockIndexer(async (req, res) => {
    assert.equal(req.headers.authorization, "Bearer test-token");
    res.end(JSON.stringify({hits: {total: {value: 0}, hits: []}}));
  }, async (url) => {
    const client = new WazuhIndexerClient({url, token:"test-token"});
    const response = await client.search({ since: "2026-11-13T08:00:00Z", min_rule_level: 3, limit: 10, offset: 0 });
    assert.deepEqual(response.hits, []);
    assert.equal(response.total, 0);
  });
});

test("Indexer HTTP 401 and malformed JSON fail safely", async () => {
  await withMockIndexer(async (_req, res) => { res.statusCode = 401; res.end("secret details must not be returned"); }, async (url) => {
    const client = new WazuhIndexerClient({url, token:"x"});
    await assert.rejects(() => client.search({since:"2026-11-13T08:00:00Z", min_rule_level:3, limit:10, offset:0}), /HTTP 401/);
  });
  await withMockIndexer(async (_req, res) => res.end("not-json"), async (url) => {
    const client = new WazuhIndexerClient({url, token:"x"});
    await assert.rejects(() => client.search({since:"2026-11-13T08:00:00Z", min_rule_level:3, limit:10, offset:0}), /JSON/);
  });
});

test("ingestion retains valid cases when one Wazuh hit is bad", async () => {
  await withStore(async (store) => {
    const alerts = [fixtureResponse.hits.hits[0], {_index:"x", _id:"bad", _source:{rule:{id:"7"}}}];
    const fakeClient = {search: async (request) => ({hits:alerts, total:3, offset:request.offset})};
    const service = new IncidentIntakeService(store, "local", fakeClient);
    const result = await service.collect({since:"2026-11-13T08:00:00Z",limit:2,offset:0});
    assert.equal(result.created, 1);
    assert.equal(result.rejected, 1);
    assert.equal(result.next_offset, 2);
    assert.equal(result.failures.length, 1);
    assert.equal(result.cases[0].incident_case.source.type, "wazuh");
  });
});

test("pagination and query parameter validation are bounded", async () => {
  await withStore(async (store) => {
    const source = {search: async () => ({hits: [], total: 0, offset:0})};
    const service = new IncidentIntakeService(store, "local", source);
    await assert.rejects(() => service.collect({limit:101}), /limit/);
    await assert.rejects(() => service.collect({offset:-1}), /offset/);
    await assert.rejects(() => service.collect({min_rule_level:99}), /min_rule_level/);
    await assert.rejects(() => service.collect({since:"bogus"}), /since/);
  });
});
