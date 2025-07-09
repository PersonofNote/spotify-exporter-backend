# Spotify Collect Backend

This is the backend server for the Spotify Collect application that allows users to fetch and download their Spotify playlist information.

## Security Features

- **Rate Limiting**: Implements rate limiting on all endpoints to prevent abuse
- **Environment-based Debug Logging**: Sensitive debug information only shown in development
- **Secure Session Management**: Uses secure cookies in production with proper SameSite settings
- **Input Validation**: Validates Spotify IDs and request structure
- **Error Sanitization**: Sanitizes error messages to prevent information leakage
- **Helmet Security Headers**: Adds security headers in production
- **CORS Configuration**: Properly configured for frontend domains

## Setup Instructions

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Environment Configuration**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` file with your actual values:
   - Get Spotify API credentials from [Spotify Developer Dashboard](https://developer.spotify.com/dashboard/applications)
   - Set redirect URI in Spotify app to: `http://127.0.0.1:5173/auth/callback` (for development)
   - Generate a secure session secret (32+ characters)
   - Set appropriate URLs for your deployment

3. **Required Environment Variables**
   - `SPOTIFY_CLIENT_ID`: Your Spotify app client ID
   - `SPOTIFY_CLIENT_SECRET`: Your Spotify app client secret
   - `SPOTIFY_REDIRECT_URI`: OAuth redirect URI (should match your Spotify app settings)
   - `SESSION_SECRET`: Long random string for session encryption
   - `NODE_ENV`: Set to 'production' for production deployment
   - `PORT`: Port to run the server (default: 3001)
   - `FRONTEND_URL`: Frontend URL (required in production, must be HTTPS)

4. **Development**
   ```bash
   npm start
   ```

5. **Production Deployment**
   - Set `NODE_ENV=production`
   - Set `FRONTEND_URL` to your HTTPS frontend domain
   - Ensure all environment variables are set
   - Use a process manager like PM2 for production

## API Endpoints

### Authentication
- `GET /auth/login` - Start Spotify OAuth flow
- `GET /auth/callback` - Handle OAuth callback

### API Routes (require authentication)
- `GET /api/status` - Check authentication status
- `GET /api/playlists` - Get user's playlists
- `GET /api/playlists/:id/tracks` - Get tracks for a playlist
- `POST /api/download` - Download selected tracks in various formats

### Development Only
- `GET /api/session-test` - Test session functionality (dev only)
- `GET /api/test-session/:sessionId` - Test specific session (dev only)

## Rate Limits

- **Auth endpoints**: 25 requests per 5 minutes per IP
- **API endpoints**: 100 requests per 15 minutes per IP  
- **Download endpoint**: 10 requests per 15 minutes per IP

## Security Considerations

- Sessions are stored in files under `./sessions/` directory
- Session files are automatically cleaned up
- All sensitive data is only logged in development mode
- Production deployment requires HTTPS for secure cookies
- Input validation prevents malicious requests
- Error messages are sanitized to prevent information disclosure

## Deployment Checklist

- [ ] Set `NODE_ENV=production`
- [ ] Configure all required environment variables
- [ ] Set `FRONTEND_URL` to HTTPS domain
- [ ] Ensure Spotify app redirect URI matches your domain
- [ ] Use process manager (PM2, systemd, etc.)
- [ ] Set up reverse proxy (nginx, Apache, etc.)
- [ ] Configure SSL/TLS certificates
- [ ] Set up monitoring and logging