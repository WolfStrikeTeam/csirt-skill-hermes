# System Manifest

## Project Overview
- Name: csirt-skill-hermes
- Description: CRCT-enabled project: csirt-skill-hermes
- Created: 2026-11-13T13:04:15.382Z

## Current Status
- Current Phase: Set-up/Maintenance
- Last Updated: 2026-11-13T18:04:57.946Z

## Project Structure

- 1 tsx files
- 9 ts files
- 12 js files


## Dependencies

## Project Directory Structure

- 📂 hermes/
  - 📂 services/
    - 📄 incident-normalizer.ts
    - 📄 investigation-service.ts
    - 📄 ioc-extractor.ts
  - 📂 skills/
    - 📂 incident-summary/
    - 📂 threat-investigation/
  - 📂 tools/
    - 📂 virustotal/
      - 📄 vt-client.ts
      - 📄 vt-enricher.ts
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


## TSX Dependencies

### \landing.tsx
Dependencies:
- react

## TS Dependencies

### \index.ts
Dependencies:
- mcp-use
- zod
- ./tools/virustotal/vt.client
- ./tools/virustotal/vt.validator
- ./tools/virustotal/vt.enricher
- ./services/investigation-service
- ./services/ioc-extractor

### \mcp-env.d.ts
Dependencies:
- mcp-use/vite-client

### \hermes\types\incident.ts
No dependencies found

### \hermes\services\ioc-extractor.ts
No dependencies found

### \hermes\tools\virustotal\vt.validator.ts
Dependencies:
- ./vt.client.ts

## JS Dependencies

### \.mcp-use\cache\deps_temp_e07aa324\react.js
Dependencies:
- ./rolldown-runtime-BvCyGRYZ.js

### \.mcp-use\cache\deps_temp_e07aa324\react-dom_client.js
Dependencies:
- ./rolldown-runtime-BvCyGRYZ.js
- ./react.js
- ./react-dom.js

### \.mcp-use\cache\deps_temp_e07aa324\react-dom.js
Dependencies:
- ./rolldown-runtime-BvCyGRYZ.js
- ./react.js

### \.mcp-use\cache\deps_temp_e07aa324\react_jsx-dev-runtime.js
Dependencies:
- ./rolldown-runtime-BvCyGRYZ.js
- ./react.js

### \.mcp-use\cache\deps_temp_e07aa324\react_jsx-runtime.js
Dependencies:
- ./rolldown-runtime-BvCyGRYZ.js
- ./react.js



## Project Directory Structure

- 📂 hermes/
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

### \index.ts
Dependencies:
- mcp-use
- zod
- ./tools/virustotal/vt.client.ts
- ./tools/virustotal/vt.validator.ts
- ./tools/virustotal/vt.enricher.ts
- ./services/investigation-service.ts
- ./services/ioc-extractor.ts

### \mcp-env.d.ts
Dependencies:
- mcp-use/vite-client

### \hermes\types\incident.ts
No dependencies found

### \hermes\services\ioc-extractor.ts
No dependencies found

### \hermes\services\investigation-service.ts
Dependencies:
- ../types/incident.ts
- ./incident-normalizer.ts
- ./ioc-extractor.ts
- ../tools/virustotal/vt.validator.ts
- ../tools/virustotal/vt.enricher.ts

## TSX Dependencies

### \landing.tsx
Dependencies:
- react

## JS Dependencies

### \.mcp-use\cache\deps_temp_f3197620\rolldown-runtime-BvCyGRYZ.js
No dependencies found

### \.mcp-use\cache\deps_temp_f3197620\react_jsx-runtime.js
Dependencies:
- ./rolldown-runtime-BvCyGRYZ.js
- ./react.js

### \.mcp-use\cache\deps_temp_f3197620\react_jsx-dev-runtime.js
Dependencies:
- ./rolldown-runtime-BvCyGRYZ.js
- ./react.js

### \.mcp-use\cache\deps_temp_f3197620\react.js
Dependencies:
- ./rolldown-runtime-BvCyGRYZ.js

### \.mcp-use\cache\deps_temp_f3197620\react-dom_client.js
Dependencies:
- ./rolldown-runtime-BvCyGRYZ.js
- ./react.js
- ./react-dom.js



## Project Directory Structure

- 📂 hermes/
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

### \mcp-env.d.ts
Dependencies:
- mcp-use/vite-client

### \hermes\services\ioc-extractor.ts
No dependencies found

### \hermes\tools\virustotal\vt.validator.ts
Dependencies:
- ./vt.client.ts

## TSX Dependencies

### \landing.tsx
Dependencies:
- react



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
