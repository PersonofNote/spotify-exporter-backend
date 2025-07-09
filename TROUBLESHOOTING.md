# Session/Cookie Troubleshooting Guide

## Issue: Session ID Mismatch After Login

### Symptoms
- Backend shows "token exchange successful" and "cookie will be set"
- Frontend shows different session ID when calling `/api/status`
- Session exists but `hasAccessToken` is `false`

### Root Cause (SOLVED)
Spotify doesn't allow `localhost` redirect URIs, so we need to use `127.0.0.1`. The new auth flow:
1. User clicks login → redirected to Spotify OAuth
2. Spotify redirects to `127.0.0.1:5173/auth/callback?code=...`
3. Frontend captures code and sends to backend `/auth/exchange`
4. Backend exchanges code for tokens and sets session cookie
5. Frontend receives confirmation and shows authenticated state

### Debugging Steps

1. **Check Backend Logs**
   ```bash
   npm run dev
   ```
   Look for:
   - `=== CALLBACK SESSION DEBUG ===` - Shows session ID and cookie settings after auth
   - `=== STATUS ENDPOINT DEBUG ===` - Shows session ID when frontend checks status

2. **Check Frontend Console**
   - Open browser DevTools
   - Check Console for cookie debugging logs
   - Look for `Document cookies:` logs

3. **Test Cookie Endpoints**
   ```bash
   # Debug cookies
   curl -v "http://localhost:3001/api/debug-cookies"
   
   # Test session
   curl -v "http://localhost:3001/api/session-test"
   ```

4. **Check Browser Cookies**
   - Open DevTools → Application → Cookies
   - Check for `spotify-session` cookie on `localhost:3001`
   - Check for `spotify-session` cookie on `localhost:5173`

### Expected Behavior (New Auth Flow)
1. User clicks "Login with Spotify"
2. Redirected to Spotify OAuth
3. Spotify redirects to `http://127.0.0.1:5173/auth/callback?code=...`
4. Frontend extracts auth code and sends to backend `/auth/exchange`
5. Backend exchanges code for tokens and sets session cookie
6. Frontend receives success response and sets authenticated state
7. Subsequent API calls use the same session cookie

### Common Issues & Solutions

#### Issue 1: Cookie Domain Problems
**Problem**: Cookie set for wrong domain
**Solution**: Updated backend to not set explicit domain for localhost

#### Issue 2: CORS Configuration
**Problem**: Cookies not being sent with CORS requests
**Solution**: Updated CORS to include `exposedHeaders: ['Set-Cookie']`

#### Issue 3: Vite Proxy Configuration
**Problem**: Vite proxy not forwarding cookies properly
**Solution**: Updated Vite config with proper proxy settings

#### Issue 4: Session Configuration
**Problem**: Session not persisting properly
**Solution**: Set `resave: false` and `rolling: true`

### Manual Test Steps

1. **Start Backend**
   ```bash
   npm run dev
   ```

2. **Start Frontend**
   ```bash
   cd ../frontend && npm run dev
   ```

3. **Test Auth Flow**
   - Visit: http://127.0.0.1:5173
   - Click "Login with Spotify"
   - Should redirect to Spotify OAuth
   - After OAuth, should redirect to http://127.0.0.1:5173/auth/callback
   - Frontend should automatically exchange code and redirect to main app
   - Check browser console for debugging info

4. **Verify Session**
   - After login, check DevTools → Application → Cookies
   - Should see `spotify-session` cookie for 127.0.0.1
   - Frontend should show authenticated state with playlists loaded

### Debug Endpoints (Development Only)

- **Cookie Debug**: `GET /api/debug-cookies`
  - Shows current session info and cookie headers
- **Session Test**: `GET /api/session-test`  
  - Tests session creation and retrieval
- **Status Check**: `GET /api/status`
  - Shows authentication status

### If Issue Persists

1. **Clear All Cookies**
   - DevTools → Application → Storage → Clear storage
   - Restart both backend and frontend

2. **Check Environment**
   - Verify `.env` has all required variables
   - Check `SPOTIFY_REDIRECT_URI` matches exactly

3. **Verify Spotify App Settings**
   - Redirect URI: `http://127.0.0.1:5173/auth/callback`
   - App must be in development mode
   - Make sure .env SPOTIFY_REDIRECT_URI matches exactly

### Production Considerations

- Set `NODE_ENV=production`
- Use HTTPS domains
- Set `FRONTEND_URL` to production domain
- Ensure cookies are secure (`secure: true`)
- Update Spotify app redirect URI to production URL