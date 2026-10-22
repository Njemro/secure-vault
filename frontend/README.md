# Secure Vault — Frontend

React + JavaScript + Vite single-page application (SPA) foundation for the
Secure Vault project. This is the initial application shell only.

## Status

- Navigation shell with placeholder pages: **Dashboard**, **My Secrets**,
  **Shared With Me**, and **Security Settings**.
- **Mock data only.** No real login, Keycloak/OIDC, cookies, API calls,
  cryptography, secret storage, or sharing logic yet.
- Client-side cryptography (Web Crypto API) and backend integration will be
  added in later steps, per `AGENTS.md`.

## Getting started

```bash
npm install
npm run dev      # start the dev server (http://localhost:5173)
```

## Available scripts

| Script            | Description                                  |
| ----------------- | -------------------------------------------- |
| `npm run dev`     | Start the Vite dev server with HMR.          |
| `npm run build`   | Production build into `dist/`.               |
| `npm run preview` | Preview the production build locally.        |
| `npm run lint`    | Run ESLint over the project.                 |

## API proxy

During development, requests to `/api/*` are proxied to the Spring Cloud
Gateway at `http://localhost:8000` (see `vite.config.js`). No concrete API
endpoints are defined yet.
