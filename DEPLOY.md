# LeadFlow — Azure Deployment Guide

## Prerequisites on the Azure VM

1. **Node.js 22+**
   ```bash
   curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
   sudo apt-get install -y nodejs
   ```

2. **PM2** (keeps the server running after logout / on reboot)
   ```bash
   sudo npm install -g pm2
   ```

3. **Git**
   ```bash
   sudo apt-get install -y git
   ```

## First-Time Setup on Azure

```bash
# Clone the repo (use your GitHub Personal Access Token when prompted)
git clone https://github.com/YOUR_GITHUB_USERNAME/leadflow.git /opt/leadflow
cd /opt/leadflow

# Start with PM2 — gives it the name "leadflow"
pm2 start server.js --name leadflow

# Save PM2 config so it restarts on reboot
pm2 save
pm2 startup   # follow the printed command to enable on boot
```

## Environment / Port

By default LeadFlow listens on port **3031**. To expose it on port 80/443:
- Use **Azure Application Gateway** or **nginx** as a reverse proxy, OR
- Change the `PORT` constant at the top of `server.js` to 80 (requires root or authbind)

### Recommended: nginx reverse proxy

```nginx
server {
    listen 80;
    server_name your-domain-or-azure-ip;

    location / {
        proxy_pass http://localhost:3031;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

```bash
sudo apt install nginx
sudo nano /etc/nginx/sites-available/leadflow   # paste config above
sudo ln -s /etc/nginx/sites-available/leadflow /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

## Deploying Updates

Every time changes are made locally and pushed to GitHub:

```bash
# On the Azure server
cd /opt/leadflow
git pull origin main
pm2 restart leadflow
```

That's the entire deployment process — pull + restart.

## Database

The database (`leadflow.db`) is **not in the repo**. It is created automatically the first time the server starts. On the Azure server it will live at `/opt/leadflow/leadflow.db`.

**To migrate your existing data from Blair's laptop to Azure:**
1. Copy `leadflow.db` from `C:\Users\BlairBass\Claude Leads\leadflow.db`
2. Upload it to `/opt/leadflow/leadflow.db` on the Azure VM via SCP or Azure portal
3. Restart: `pm2 restart leadflow`

## SSO Redirect URIs on Azure

Once you have the Azure VM's domain/IP, update your OAuth apps:
- **Google:** Add `https://your-domain/auth/google/callback` in Google Cloud Console
- **Microsoft:** Add `https://your-domain/auth/microsoft/callback` in Azure App Registrations
- **LeadFlow:** Update SSO Base URL in Maintenance → SSO / Auth

## Backups

```bash
# Simple daily backup script — run via cron
cp /opt/leadflow/leadflow.db /opt/leadflow/backups/leadflow-$(date +%Y%m%d).db
```

Add to crontab (`crontab -e`):
```
0 2 * * * cp /opt/leadflow/leadflow.db /opt/backups/leadflow-$(date +\%Y\%m\%d).db
```
