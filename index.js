require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const axios = require('axios');
const querystring = require('querystring');
const { Parser: CsvParser } = require('json2csv');
const rateLimit = require('express-rate-limit');

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
    secure: process.env.NODE_ENV === 'production' ? true : false, // only true for HTTPS
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
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
    res.redirect(`${FRONTEND_URI}/?auth=success`);
  } catch (err) {
    res.redirect(`${FRONTEND_URI}/?error=token_exchange_failed`);
  }
});

// Helper middleware to check authentication
function requireAuth(req, res, next) {
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

// Helper to normalize text fields to NFC
function normalizeText(str) {
  return typeof str === 'string' ? str.normalize('NFC') : '';
}

function normalizeData(data) {
  return data.map(pl => ({
    ...pl,
    name: normalizeText(pl.name),
    tracks: (pl.tracks || []).map(track => ({
      ...track,
      title: normalizeText(track.title),
      artists: (track.artists || []).map(normalizeText)
    }))
  }));
}

// Helper to generate file content
function generateFile(data, format) {
  const safeData = normalizeData(data);
  if (format === 'json') {
    return { content: JSON.stringify(safeData, null, 2), type: 'application/json; charset=utf-8' };
  } else if (format === 'csv') {
    // Flatten data for CSV
    const rows = [];
    safeData.forEach(pl => {
      (pl.tracks || []).forEach(track => {
        rows.push({
          playlist: pl.name,
          title: track.title,
          artists: (track.artists || []).join(', ')
        });
      });
    });
    const parser = new CsvParser({ fields: ['playlist', 'title', 'artists'] });
    return { content: parser.parse(rows), type: 'text/csv; charset=utf-8' };
  } else if (format === 'txt') {
    // Simple text format
    let txt = '';
    safeData.forEach(pl => {
      txt += `Playlist: ${pl.name}\n`;
      (pl.tracks || []).forEach(track => {
        txt += `  - ${track.title} – ${track.artists.join(', ')}\n`;
      });
      txt += '\n';
    });
    return { content: txt, type: 'text/plain; charset=utf-8' };
  }
  throw new Error('Unsupported format');
}

const downloadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 download requests per windowMs
  message: 'Too many download requests from this IP, please try again later.'
});

// Helper to sleep for ms milliseconds
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Helper to chunk an array into batches
function chunkArray(arr, maxTracksPerBatch, tracksByPlaylist) {
  const batches = [];
  let currentBatch = [];
  let currentCount = 0;
  for (const sel of arr) {
    const numTracks = sel.trackIds.length;
    if (currentCount + numTracks > maxTracksPerBatch && currentBatch.length > 0) {
      batches.push(currentBatch);
      currentBatch = [];
      currentCount = 0;
    }
    currentBatch.push(sel);
    currentCount += numTracks;
  }
  if (currentBatch.length > 0) {
    batches.push(currentBatch);
  }
  return batches;
}

// Updated fetchPlaylistsAndTracks to support batching and delays
async function fetchPlaylistsAndTracksBatched(accessToken, selection, batchSize = 1000, delayMs = 500) {
  // selection: [{ playlistId, trackIds: [trackId, ...] }]
  const batches = chunkArray(selection, batchSize);
  let allResults = [];
  let skippedTracks = [];
  for (let i = 0; i < batches.length; i++) {
    const batch = batches[i];
    const batchResults = [];
    for (const sel of batch) {
      // Fetch playlist metadata
      const plRes = await axios.get(`https://api.spotify.com/v1/playlists/${sel.playlistId}`, {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      const pl = plRes.data;
      // Fetch all tracks for this playlist (handle pagination)
      let tracks = [];
      let url = `https://api.spotify.com/v1/playlists/${sel.playlistId}/tracks?limit=100`;
      while (url) {
        const trRes = await axios.get(url, {
          headers: { Authorization: `Bearer ${accessToken}` }
        });
        tracks = tracks.concat(trRes.data.items.map(item => item.track));
        url = trRes.data.next;
      }
      // Filter tracks to only those selected, skip null track IDs
      const selectedTracks = [];
      for (const trackId of sel.trackIds) {
        if (trackId === null) {
          // Find the track in the playlist to get its title
          const track = tracks.find(t => t && t.id === null);
          if (track) {
            skippedTracks.push({
              playlistName: pl.name,
              title: track.name,
              reason: 'null_track_id'
            });
          }
          continue;
        }
        const track = tracks.find(t => t && t.id === trackId);
        if (track) {
          selectedTracks.push({
            id: track.id,
            title: track.name,
            artists: (track.artists || []).map(a => a.name)
          });
        } else {
          // Track not found in playlist
          skippedTracks.push({
            playlistName: pl.name,
            title: `Unknown track (ID: ${trackId})`,
            reason: 'track_not_found'
          });
        }
      }
      batchResults.push({
        id: pl.id,
        name: pl.name,
        tracks: selectedTracks
      });
    }
    allResults = allResults.concat(batchResults);
    if (i < batches.length - 1) {
      await sleep(delayMs); // Wait before next batch
    }
  }
  return { results: allResults, skippedTracks };
}

app.post(
  '/api/download',
  requireAuth,
  downloadLimiter,
  express.json({ limit: '1mb' }),
  async (req, res) => {
    const { selection, format } = req.body;
    if (!selection || !Array.isArray(selection) || !format) {
      return res.status(400).json({ error: 'Missing selection or format' });
    }
    // Validate selection structure
    for (const sel of selection) {
      if (
        typeof sel.playlistId !== 'string' ||
        !Array.isArray(sel.trackIds) ||
        !sel.trackIds.every(id => typeof id === 'string' || id === null)
      ) {
        return res.status(400).json({ error: 'Invalid selection structure' });
      }
    }
    try {
      const { results: data, skippedTracks } = await fetchPlaylistsAndTracksBatched(req.session.access_token, selection, 1000, 500);
      const { content, type } = generateFile(data, format);
      res.setHeader('Content-Disposition', `attachment; filename=spotify_export.${format}`);
      res.setHeader('Content-Type', type);
      res.setHeader('X-Skipped-Tracks', JSON.stringify(skippedTracks));
      res.send(content);
    } catch (err) {
      // Add detailed logging
      console.error('Download error:', err.response?.data || err.message, err.stack);
      res.status(500).json({ error: 'Failed to generate file', details: err.response?.data || err.message });
    }
  }
);

app.get('/debug/session', (req, res) => {
  res.json({ session: req.session });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
