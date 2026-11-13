import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { IncidentCase, IntakeResult } from "../../types/incident-intake.js";

const CASE_ID_PATTERN = /^INC-[A-F0-9]{24}$/;

/** File-backed MVP store: atomic create, persisted idempotency across restarts. */
export class IncidentStore {
  constructor(private readonly directory: string) {}

  private filePath(caseId: string): string {
    if (!CASE_ID_PATTERN.test(caseId)) throw new Error("case_id tidak valid");
    return join(this.directory, `${caseId}.json`);
  }

  async get(caseId: string): Promise<IncidentCase | null> {
    const file = this.filePath(caseId);
    let raw: string;
    try {
      raw = await readFile(file, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw error;
    }
    const data = JSON.parse(raw) as IncidentCase;
    if (data.case_id !== caseId || data.schema_version !== "1.0") {
      throw new Error("File insiden rusak atau tidak sesuai skema");
    }
    return data;
  }

  async createOrGet(incident: IncidentCase): Promise<IntakeResult> {
    const file = this.filePath(incident.case_id);
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    try {
      await writeFile(file, JSON.stringify(incident, null, 2) + "\n", {
        encoding: "utf8", flag: "wx", mode: 0o600,
      });
      return { status: "created", incident_case: incident };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const existing = await this.get(incident.case_id);
      if (!existing) throw new Error("Kasus sudah ada tetapi gagal dibaca");
      return { status: "existing", incident_case: existing };
    }
  }

  async list(limit = 50): Promise<IncidentCase[]> {
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      throw new Error("limit harus 1-100");
    }
    let entries: string[];
    try {
      entries = await readdir(this.directory);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
    // MVP only; for large datasets replace with a proper indexed repository.
    if (entries.length > 5000) throw new Error("Terlalu banyak kasus untuk file store; gunakan database");
    const files = entries.filter((name) => /^INC-[A-F0-9]{24}\.json$/.test(name));
    const all = await Promise.all(files.map(async (file) => this.get(file.slice(0, -5))));
    return all.filter((data): data is IncidentCase => Boolean(data))
      .sort((a, b) => b.created_at.localeCompare(a.created_at) || b.case_id.localeCompare(a.case_id))
      .slice(0, limit);
  }
}
