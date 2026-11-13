# System Manifest

## Project Overview
- Name: csirt-skill-hermes
- Description: CRCT-enabled project: csirt-skill-hermes
- Created: 2026-11-13T13:04:15.382Z

## Current Status
- Current Phase: Set-up/Maintenance
- Last Updated: 2026-11-13T17:40:50.400Z

## Project Structure

- 9 ts files
- 1 tsx files


## Dependencies

## Project Directory Structure

- 📂 hermes/
  - 📂 config/
  - 📂 persona/
  - 📂 services/
    - 📄 incident-normalizer.ts
    - 📄 investigation-service.ts
    - 📄 ioc-extractor.ts
  - 📂 skills/
    - 📂 incident-summary/
    - 📂 threat-investigation/
  - 📂 tools/
    - 📂 virustotal/
      - 📄 vt.client.ts
      - 📄 vt.enricher.ts
      - 📄 vt.validator.ts
  - 📂 types/
    - 📄 incident.ts
  - 📄 config.example.yaml
- 📂 public/
  - 📄 icon.svg
- 📄 index.ts
- 📄 landing.tsx
- 📄 LICENSE
- 📄 mcp-env.d.ts


## TS Dependencies

### \mcp-env.d.ts
Dependencies:
- mcp-use/vite-client

### \index.ts
Dependencies:
- mcp-use/server
- zod
- ./tools/virustotal/vt.client.ts
- ./tools/virustotal/vt.validator.ts
- ./tools/virustotal/vt.enricher.ts
- ./services/investigation-service.ts
- ./services/ioc-extractor.ts

### \hermes\types\incident.ts
No dependencies found

### \hermes\services\incident-normalizer.ts
Dependencies:
- ../types/incident.js

### \hermes\services\investigation-service.ts
Dependencies:
- ../types/incident.js
- ./incident-normalizer.js
- ./ioc-extractor.js
- ../tools/virustotal/vt.validator.js
- ../tools/virustotal/vt.enricher.js

## TSX Dependencies

### \landing.tsx
Dependencies:
- react



## Project Directory Structure

- 📂 hermes/
  - 📂 config/
  - 📂 persona/
  - 📂 services/
  - 📂 skills/
    - 📂 incident-summary/
    - 📂 threat-investigation/
  - 📂 tools/
  - 📄 config.example.yaml
- 📂 public/
  - 📄 icon.svg
- 📄 index.ts
- 📄 landing.tsx
- 📄 LICENSE
- 📄 mcp-env.d.ts


## TS Dependencies

### \mcp-env.d.ts
Dependencies:
- mcp-use/vite-client

### \index.ts
Dependencies:
- mcp-use

## TSX Dependencies

### \landing.tsx
Dependencies:
- react



## Project Directory Structure

- 📂 hermes/
  - 📂 skills/
    - 📂 security/
      - 📂 incident-summary/
        ...
  - 📄 config.example.yaml
- 📂 public/
  - 📄 icon.svg
- 📄 index.ts
- 📄 landing.tsx
- 📄 LICENSE
- 📄 mcp-env.d.ts


## TS Dependencies

### \index.ts
Dependencies:
- mcp-use

### \mcp-env.d.ts
Dependencies:
- mcp-use/vite-client

## TSX Dependencies

### \landing.tsx
Dependencies:
- react



## Project Directory Structure

- 📂 public/
  - 📄 icon.svg
- 📄 index.ts
- 📄 landing.tsx
- 📄 LICENSE
- 📄 mcp-env.d.ts


## TSX Dependencies

### \landing.tsx
Dependencies:
- react

## TS Dependencies

### \mcp-env.d.ts
Dependencies:
- mcp-use/vite-client

### \index.ts
Dependencies:
- mcp-use
- zod



## Project Directory Structure

- 📂 public/
  - 📄 icon.svg
- 📄 index.ts
- 📄 landing.tsx
- 📄 LICENSE
- 📄 mcp-env.d.ts


## TSX Dependencies

### \landing.tsx
Dependencies:
- react

## TS Dependencies

### \index.ts
Dependencies:
- mcp-use
- zod

### \mcp-env.d.ts
Dependencies:
- mcp-use/vite-client



## Key Components
- TBD

## Integration Points
- TBD

## Technical Considerations
- TBD

## Implementation Notes
- TBD
