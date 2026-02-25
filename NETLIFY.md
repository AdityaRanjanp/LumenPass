# Netlify Setup For This Project

This project is a Flask backend app. Netlify can be used as your public website domain by proxying traffic to your deployed backend.

## 1. Deploy backend first

Deploy this app to Render or Railway using:

- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app --bind 0.0.0.0:$PORT`

Set env vars:

- `FLASK_SECRET_KEY`
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`

## 2. Configure Netlify proxy

Edit `netlify.toml` and replace:

- `https://YOUR_BACKEND_URL` with your real backend URL  
  Example: `https://lumenpass.onrender.com`

## 3. Deploy to Netlify

1. Push project to GitHub.
2. In Netlify, create site from that repo.
3. Build command: leave empty.
4. Publish directory: `netlify`
5. Deploy.

After deployment, your Netlify domain will serve your Flask app through proxy redirects.

## 4. Important

- Server-side webcam scanning (`/scan`) will not work on normal cloud hosts without camera hardware.
- For cloud usage, scanning should be moved to browser-side camera JavaScript in a future update.

