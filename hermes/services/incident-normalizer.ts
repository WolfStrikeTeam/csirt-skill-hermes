import type { IncidentInput } from "../types/incident.js";

export function normalizeIncident(
  input: IncidentInput
): IncidentInput {
  return {
    ...input,
    incidentId: input.incidentId.trim(),
    title: input.title.trim(),
    description: input.description.trim(),
    observables: input.observables ?? [],
    evidence: input.evidence ?? [],
  };
}