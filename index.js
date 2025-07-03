require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const axios = require('axios');
const querystring = require('querystring');

const app = express();
const PORT = process.env.PORT || 3001;

const SPOTIFY_CLIENT_ID = process.env.SPOTIFY_CLIENT_ID;
const SPOTIFY_CLIENT_SECRET = process.env.SPOTIFY_CLIENT_SECRET;
const SPOTIFY_REDIRECT_URI = process.env.SPOTIFY_REDIRECT_URI;
const FRONTEND_URI = 'http://127.0.0.1:5173';

const SCOPES = [
  'playlist-read-private',
  'playlist-read-collaborative',
  'user-read-private'
].join(' ');

app.use(cors({
  origin: 'http://127.0.0.1:5173',
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // only true for HTTPS
    sameSite: 'lax' // 'none' only if using HTTPS
  }
}));

app.get('/', (req, res) => {
  res.send('Spotify Collector Backend Running');
});

app.get('/auth/login', (req, res) => {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: SPOTIFY_CLIENT_ID,
    scope: SCOPES,
    redirect_uri: SPOTIFY_REDIRECT_URI,
    show_dialog: 'true'
  });
  res.redirect(`https://accounts.spotify.com/authorize?${params.toString()}`);
});

app.get('/auth/callback', async (req, res) => {
  const code = req.query.code || null;
  if (!code) {
    return res.redirect(`${FRONTEND_URI}/?error=missing_code`);
  }
  try {
    const tokenRes = await axios.post('https://accounts.spotify.com/api/token',
      querystring.stringify({
        grant_type: 'authorization_code',
        code,
        redirect_uri: SPOTIFY_REDIRECT_URI,
        client_id: SPOTIFY_CLIENT_ID,
        client_secret: SPOTIFY_CLIENT_SECRET
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    req.session.access_token = tokenRes.data.access_token;
    req.session.refresh_token = tokenRes.data.refresh_token;
    console.log('Session after setting tokens:', req.session);
    console.log('Session ID after setting tokens:', req.sessionID);
    res.redirect(`${FRONTEND_URI}/?auth=success`);
  } catch (err) {
    res.redirect(`${FRONTEND_URI}/?error=token_exchange_failed`);
  }
});

// Helper middleware to check authentication
function requireAuth(req, res, next) {
  console.log('Session in requireAuth:', req.session);
  console.log('Session ID in requireAuth:', req.sessionID);
  if (!req.session.access_token) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
}

// Get user's playlists
app.get('/api/playlists', requireAuth, async (req, res) => {
  try {
    const playlists = [];
    let url = 'https://api.spotify.com/v1/me/playlists?limit=50';
    while (url) {
      const response = await axios.get(url, {
        headers: { Authorization: `Bearer ${req.session.access_token}` }
      });
      playlists.push(...response.data.items.map(p => ({
        id: p.id,
        name: p.name
      })));
      url = response.data.next;
    }
    res.json({ playlists });
  } catch (err) {
    console.error('Error fetching playlists:', err.response ? err.response.data : err.message);
    console.error('Session info:', req.session);
    res.status(err.response?.status || 500).json({ error: 'Failed to fetch playlists', details: err.response?.data || err.message });
  }
});

// Get tracks for a playlist
app.get('/api/playlists/:id/tracks', requireAuth, async (req, res) => {
  const playlistId = req.params.id;
  try {
    const tracks = [];
    let url = `https://api.spotify.com/v1/playlists/${playlistId}/tracks?limit=100`;
    while (url) {
      const response = await axios.get(url, {
        headers: { Authorization: `Bearer ${req.session.access_token}` }
      });
      tracks.push(...response.data.items.map(item => {
        const t = item.track;
        return {
          id: t.id,
          title: t.name,
          artists: t.artists.map(a => a.name)
        };
      }));
      url = response.data.next;
    }
    res.json({ tracks });
  } catch (err) {
    console.error('Error fetching tracks:', err.response ? err.response.data : err.message);
    console.error('Session info:', req.session);
    res.status(err.response?.status || 500).json({ error: 'Failed to fetch tracks', details: err.response?.data || err.message });
  }
});

app.get('/debug/session', (req, res) => {
  res.json({ session: req.session });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
