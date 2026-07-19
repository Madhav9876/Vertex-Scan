# Google OAuth Setup Guide

This guide explains how to set up Google OAuth for Vertex Scan.

## Prerequisites

1. A Google Cloud Platform account
2. Your application deployed or running locally

## Step 1: Create Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the **Google Identity Platform API**

## Step 2: Configure OAuth Consent Screen

1. Navigate to **APIs & Services > OAuth consent screen**
2. Select **External** user type
3. Fill in required fields:
   - App name: Vertex Scan
   - User support email: your-email@example.com
   - Developer contact email: your-email@example.com
4. Add scopes (if needed): `email`, `profile`, `openid`
5. Save and continue

## Step 3: Create OAuth Credentials

1. Navigate to **APIs & Services > Credentials**
2. Click **Create Credentials > OAuth client ID**
3. Application type: **Web application**
4. Name: Vertex Scan Web Client
5. **Authorized JavaScript origins** (REQUIRED - for GIS token flow):
    - Development: `http://localhost`
    - Production: `https://vertex-scan.vercel.app`
6. **Authorized redirect URIs** (OPTIONAL - for traditional OAuth flow, not required for GIS):
    - Development: `http://localhost/login`
    - Production: `https://vertex-scan.vercel.app/login`

## Step 4: Configure Environment Variables

### Frontend (.env or .env.local)
```env
VITE_API_URL=http://localhost:3001
VITE_GOOGLE_CLIENT_ID=YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com
```

### Production (.env.production)
```env
VITE_API_URL=https://vertex-scan.onrender.com
VITE_GOOGLE_CLIENT_ID=YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com
```

> **IMPORTANT:** The frontend `VITE_GOOGLE_CLIENT_ID` and the backend `GOOGLE_CLIENT_ID`
> (set in Render / `.env`) MUST be the **exact same** OAuth client ID. If they differ,
> Google login fails with "Authentication failed" because the backend rejects the token's
> `aud` (audience) claim. Create your *own* OAuth client in Google Cloud Console — do not
> reuse a client ID from this repository or third parties.

## Step 5: Run Database Migration

The migration will add OAuth-related columns to the users table:
```bash
npm run migrate
```

## Step 6: Test the Integration

1. Start the development server:
   ```bash
   # Backend
   cd backend && npm run dev

   # Frontend
   cd frontend && npm run dev
   ```

2. Visit `http://localhost:5173/login`
3. You should see "Or continue with" and the Google Sign-In button

## How It Works

1. User clicks the Google Sign-In button
2. Google returns an ID token (JWT credential)
3. Frontend sends the credential to `/api/oauth/google`
4. Backend verifies the Google token with Google's API
5. If user exists, logs them in; if not, creates a new account
6. Returns a JWT token for your app's authentication

## Security Considerations

- The Google ID token is verified server-side before creating/updating users
- Users created via Google OAuth have `auth_provider: 'google'` in the database
- Existing users with the same email will have their account linked to Google
- All OAuth events are logged in the `security_events` table