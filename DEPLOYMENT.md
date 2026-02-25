# Deployment Guide (Free + Mobile Friendly)

## 1. Recommended free deploy target

Use **Render free web service** with this repo.
`render.yaml` is already included for one-click setup.

## 2. Required environment variables

Set these in Render (or any host):

- `FLASK_SECRET_KEY` = long random string
- `ADMIN_USERNAME` = admin username
- `ADMIN_PASSWORD` = admin password
- `VISITOR_DB_PATH` = `visitors.db` (or custom path)

Generate secret:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

## 3. Quick Render deployment steps

1. Push project to GitHub.
2. Open Render dashboard -> `New` -> `Blueprint`.
3. Select this repository (Render will read `render.yaml`).
4. Add `ADMIN_PASSWORD` when asked.
5. Click deploy.

## 4. Mobile scanning support

Cloud deployment now supports mobile browser QR scanning from Admin dashboard:

- Android Chrome/Firefox/Edge supported.
- iOS Safari/Chrome supported (camera permission required).
- File-upload QR fallback is available in scanner widget.

Note:
- `/scan` (OpenCV desktop mode) still requires server-local webcam.
- For cloud usage, use `Start Mobile Camera Scan` button in admin page.

## 5. Can you change site after deploy?

Yes.

If you update code and push to GitHub, Render auto-redeploys.
Your latest changes go live after each successful deploy.

## 6. Data persistence note (important)

With free tiers, storage behavior depends on host plan.
If you need guaranteed long-term visitor history, move to managed database or persistent disk.

