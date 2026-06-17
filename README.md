# LeadFlow — Redhawk BD Intelligence Platform

Internal business development CRM for Redhawk Federal Solutions. Tracks sales pipeline, runs nightly AI prospect research, and exports leads to Pipedrive.

## Stack
- **Frontend:** Single-file React 18 app (CDN + Babel Standalone)
- **Backend:** Node.js HTTP server (`server.js`), port 3031
- **Database:** SQLite via `node:sqlite` (WAL mode), file `leadflow.db`
- **AI:** Anthropic Claude Haiku via API
- **Enrichment:** Apollo.io API

## Files
| File | Purpose |
|------|---------|
| `server.js` | Node.js backend — API routes, nightly jobs, auth, SSO |
| `leads.html` | Full frontend app served at `/` |
| `leadflow.db` | SQLite database (**not in repo** — stays on each server) |

## Local Development

```powershell
# Start the server
node server.js

# Access at
http://localhost:3031
```

## Production Deployment (Azure)

See [DEPLOY.md](DEPLOY.md) for full Azure setup and deployment instructions.

## Updating Production from Local Changes

```powershell
# 1. Commit and push changes locally
git add server.js leads.html
git commit -m "describe what changed"
git push origin main

# 2. On the Azure server, pull and restart
git pull origin main
pm2 restart leadflow   # or: node server.js
```

## Remote Access (Local Laptop)

```powershell
cloudflared tunnel --url http://localhost:3031
```

## Data & Backups

The database file `leadflow.db` is **not in version control** — it lives only on the server running LeadFlow. Back it up regularly by copying to Azure Blob Storage or another safe location.

## Security Notes
- All data stays on your own server — nothing sent to third parties except Anthropic API (research) and Apollo.io (enrichment)
- SSO restricted to `@redhawkdigital.ai` and `@agr-us.com` domains
- Sessions expire after 30 days
