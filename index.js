console.log('🚀 Fresh build deployed at', new Date().toISOString());
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const querystring = require('querystring');
const { Parser: CsvParser } = require('json2csv');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

// In-memory quota tracking (resets on server restart)
class InMemoryQuotaTracker {
  constructor() {
    this.quotas = new Map();
    // Clean up old quotas daily
    setInterval(() => this.cleanupOldQuotas(), 24 * 60 * 60 * 1000);
  }

  getUserQuota(userId) {
    const today = new Date().toISOString().split('T')[0];
    const userKey = `${userId}:${today}`;
    
    if (!this.quotas.has(userKey)) {
      this.quotas.set(userKey, {
        apiCalls: 0,
        downloads: 0,
        downloadedTracks: 0
      });
    }
    
    return this.quotas.get(userKey);
  }

  incrementApiCalls(userId, count = 1) {
    const quota = this.getUserQuota(userId);
    quota.apiCalls += count;
    return quota.apiCalls;
  }

  incrementDownloads(userId, trackCount = 0) {
    const quota = this.getUserQuota(userId);
    quota.downloads += 1;
    quota.downloadedTracks += trackCount;
    return quota;
  }

  checkApiLimit(userId, limit = 5000) {
    const quota = this.getUserQuota(userId);
    return quota.apiCalls < limit;
  }

  checkDownloadLimit(userId, limit = 20) {
    const quota = this.getUserQuota(userId);
    return quota.downloads < limit;
  }

  getQuotaStatus(userId) {
    const quota = this.getUserQuota(userId);
    return {
      date: new Date().toISOString().split('T')[0],
      apiCalls: quota.apiCalls,
      apiLimit: 5000,
      downloads: quota.downloads,
      downloadLimit: 20,
      downloadedTracks: quota.downloadedTracks
    };
  }

  cleanupOldQuotas() {
    const today = new Date().toISOString().split('T')[0];
    for (const [key] of this.quotas) {
      const [, date] = key.split(':');
      if (date !== today) {
        this.quotas.delete(key);
      }
    }
  }
}

const quotaTracker = new InMemoryQuotaTracker();

// Client Credentials token management for public API access
let clientCredentialsToken = null;
let tokenExpiry = null;

async function getClientCredentialsToken() {
  // Check if we have a valid token
  if (clientCredentialsToken && tokenExpiry && Date.now() < tokenExpiry) {
    return clientCredentialsToken;
  }

  try {
    const response = await axios.post('https://accounts.spotify.com/api/token', 
      querystring.stringify({
        grant_type: 'client_credentials'
      }), {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Basic ${Buffer.from(`${SPOTIFY_CLIENT_ID}:${SPOTIFY_CLIENT_SECRET}`).toString('base64')}`
        }
      }
    );

    clientCredentialsToken = response.data.access_token;
    tokenExpiry = Date.now() + (response.data.expires_in * 1000) - 60000; // Refresh 1 minute early
    
    return clientCredentialsToken;
  } catch (error) {
    console.error('Failed to get client credentials token:', error.response?.data || error.message);
    throw new Error('Failed to authenticate with Spotify API');
  }
}

// Playlist URL parsing and validation
function extractPlaylistId(url) {
  if (!url || typeof url !== 'string') {
    return null;
  }

  // Sanitize input - remove any potential XSS or injection attempts
  const sanitizedUrl = url.trim().replace(/[<>'"]/g, '');
  
  // Spotify playlist URL patterns
  const patterns = [
    /https?:\/\/open\.spotify\.com\/playlist\/([a-zA-Z0-9]{22})/,
    /spotify:playlist:([a-zA-Z0-9]{22})/,
    /^([a-zA-Z0-9]{22})$/ // Just the ID itself
  ];

  for (const pattern of patterns) {
    const match = sanitizedUrl.match(pattern);
    if (match) {
      return match[1];
    }
  }

  return null;
}

// Validate Spotify playlist ID format
function isValidPlaylistId(id) {
  return typeof id === 'string' && /^[a-zA-Z0-9]{22}$/.test(id);
}

// JWT utility functions
function generateJWT(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '24h' });
}

function verifyJWT(token) {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (error) {
    return null;
  }
}

// Environment variable validation
const requiredEnvVars = [
  'SPOTIFY_CLIENT_ID',
  'SPOTIFY_CLIENT_SECRET', 
  'SPOTIFY_REDIRECT_URI',
  'JWT_SECRET'
];

for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

const app = express();
app.set('trust proxy', 1); // Trust first proxy for secure cookies in production
const PORT = process.env.PORT || 3001;

const SPOTIFY_CLIENT_ID = process.env.SPOTIFY_CLIENT_ID;
const SPOTIFY_CLIENT_SECRET = process.env.SPOTIFY_CLIENT_SECRET;
const SPOTIFY_REDIRECT_URI = process.env.SPOTIFY_REDIRECT_URI;
const isProduction = process.env.NODE_ENV === 'production';
const FRONTEND_URL = isProduction ? process.env.FRONTEND_URL : 'http://127.0.0.1:5173';

// Validate production configuration
if (isProduction && (!process.env.FRONTEND_URL || !process.env.FRONTEND_URL.startsWith('https://'))) {
  console.error('FRONTEND_URL must be set to an HTTPS URL in production');
  process.exit(1);
}

const SCOPES = [
  'playlist-read-private',
  'playlist-read-collaborative',
  'user-read-private'
].join(' ');

app.use(cors({
  origin: isProduction ? FRONTEND_URL : 'http://127.0.0.1:5173',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 200
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Security headers for production
if (isProduction) {
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'", "https://accounts.spotify.com", "https://api.spotify.com"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
      },
    },
  }));
}

app.use((req, res, next) => {
  // Allow the popup window to access window.opener
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  next();
});



// Auth check middleware
const requireAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ 
      error: 'Authentication required. Please provide a valid JWT token in Authorization header.'
    });
  }
  
  const token = authHeader.substring(7); // Remove 'Bearer ' prefix
  const decoded = verifyJWT(token);
  
  if (!decoded) {
    return res.status(401).json({ 
      error: 'Invalid or expired token. Please authenticate again.'
    });
  }
  
  // Add user data to request object
  req.user = {
    id: decoded.user_id,
    access_token: decoded.access_token,
    refresh_token: decoded.refresh_token
  };
  
  next();
};

// Helper to validate Spotify ID format
function isValidSpotifyId(id) {
  return typeof id === 'string' && /^[a-zA-Z0-9]{22}$/.test(id);
}

// Helper to sanitize error messages
function sanitizeError(err) {
  if (err.response?.status === 401) {
    return 'Authentication failed. Please log in again.';
  } else if (err.response?.status === 403) {
    return 'Access denied. Please check your permissions.';
  } else if (err.response?.status === 404) {
    return 'Resource not found.';
  } else if (err.response?.status >= 500) {
    return 'Server error. Please try again later.';
  }
  return 'An error occurred. Please try again.';
}

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

// IP-based rate limiters (for unauthenticated requests)
const downloadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 download requests per windowMs
  message: 'Too many download requests from this IP, please try again later.'
});

const authLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 25, // limit each IP to 25 auth requests per windowMs
  message: 'Too many authentication requests from this IP, please try again later.'
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 API requests per windowMs
  message: 'Too many API requests from this IP, please try again later.'
});

const publicPlaylistLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // limit each IP to 20 public playlist requests per windowMs
  message: 'Too many public playlist requests from this IP, please try again later.'
});

// User-based quota middleware
const checkUserApiQuota = (req, res, next) => {
  if (!req.user?.id) {
    return res.status(401).json({ error: 'User not authenticated' });
  }

  if (!quotaTracker.checkApiLimit(req.user.id)) {
    const status = quotaTracker.getQuotaStatus(req.user.id);
    if (!isProduction) {
      console.log(`API quota exceeded for user ${req.user.id}: ${status.apiCalls}/${status.apiLimit}`);
    }
    return res.status(429).json({ 
      error: 'Daily API limit exceeded', 
      quota: status,
      resetTime: 'Midnight UTC',
      message: `You've used ${status.apiCalls}/${status.apiLimit} API calls today. Limit resets at midnight UTC.`
    });
  }

  next();
};

const checkUserDownloadQuota = (req, res, next) => {
  if (!req.user?.id) {
    return res.status(401).json({ error: 'User not authenticated' });
  }

  if (!quotaTracker.checkDownloadLimit(req.user.id)) {
    const status = quotaTracker.getQuotaStatus(req.user.id);
    if (!isProduction) {
      console.log(`Download quota exceeded for user ${req.user.id}: ${status.downloads}/${status.downloadLimit}`);
    }
    return res.status(429).json({ 
      error: 'Daily download limit exceeded', 
      quota: status,
      resetTime: 'Midnight UTC',
      message: `You've used ${status.downloads}/${status.downloadLimit} downloads today. Limit resets at midnight UTC.`
    });
  }

  next();
};

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


// Updated fetchPlaylistsAndTracks with API call tracking
async function fetchPlaylistsAndTracksBatchedWithTracking(accessToken, selection, batchSize = 1000, delayMs = 500, userId) {
  // selection: [{ playlistId, trackIds: [trackId, ...] }]
  const batches = chunkArray(selection, batchSize);
  let allResults = [];
  let skippedTracks = [];
  let totalApiCalls = 0;
  
  for (let i = 0; i < batches.length; i++) {
    const batch = batches[i];
    const batchResults = [];
    for (const sel of batch) {
      // Fetch playlist metadata
      const plRes = await axios.get(`https://api.spotify.com/v1/playlists/${sel.playlistId}`, {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      totalApiCalls++;
      const pl = plRes.data;
      
      // Fetch all tracks for this playlist (handle pagination)
      let tracks = [];
      let url = `https://api.spotify.com/v1/playlists/${sel.playlistId}/tracks?limit=100`;
      while (url) {
        const trRes = await axios.get(url, {
          headers: { Authorization: `Bearer ${accessToken}` }
        });
        totalApiCalls++;
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
  return { results: allResults, skippedTracks, apiCallCount: totalApiCalls };
}

app.get('/', (req, res) => {
  res.send('Spotify Collector Backend Running');
});

app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Authentication endpoints
app.get('/auth', (req, res) => {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: SPOTIFY_CLIENT_ID,
    scope: SCOPES,
    redirect_uri: SPOTIFY_REDIRECT_URI,
    show_dialog: 'true'
  });
  res.redirect(`https://accounts.spotify.com/authorize?${params.toString()}`);
});

// Handle token exchange
const STATIC_DIR = path.join(__dirname, 'public');
app.use(express.static(STATIC_DIR));

// Handle OAuth callback and generate JWT
app.get('/auth/callback', authLimiter, async (req, res) => {
  const code = req.query.code;

  if (!code) {
    return res.redirect(`${FRONTEND_URL}/auth-complete.html?success=false&error=Missing+authorization+code`);
  }

  try {
    const tokenRes = await axios.post('https://accounts.spotify.com/api/token', querystring.stringify({
      grant_type: 'authorization_code',
      code,
      redirect_uri: SPOTIFY_REDIRECT_URI,
      client_id: SPOTIFY_CLIENT_ID,
      client_secret: SPOTIFY_CLIENT_SECRET
    }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });

    const access_token = tokenRes.data.access_token;
    const refresh_token = tokenRes.data.refresh_token;

    const userRes = await axios.get('https://api.spotify.com/v1/me', {
      headers: { Authorization: `Bearer ${access_token}` }
    });
    const user_id = userRes.data.id;

    // Generate JWT token containing Spotify credentials
    const jwtToken = generateJWT({
      user_id,
      access_token,
      refresh_token
    });

    return res.redirect(`${FRONTEND_URL}/auth-complete.html?success=true&token=${encodeURIComponent(jwtToken)}&userId=${encodeURIComponent(user_id)}`);
  } catch (err) {
    console.error('Auth callback error:', err.response?.data || err.message);
    return res.redirect(`${FRONTEND_URL}/auth-complete.html?success=false&error=Authentication+failed`);
  }
});

// Get user's playlists
app.get('/api/playlists', requireAuth, checkUserApiQuota, apiLimiter, async (req, res) => {
  try {
    const playlists = [];
    let url = 'https://api.spotify.com/v1/me/playlists?limit=50';
    let apiCallCount = 0;
    
    while (url) {
      const response = await axios.get(url, {
        headers: { Authorization: `Bearer ${req.user.access_token}` }
      });
      apiCallCount++;
      
      playlists.push(...response.data.items.map(p => ({
        id: p.id,
        name: p.name
      })));
      url = response.data.next;
    }
    
    // Track API usage
    quotaTracker.incrementApiCalls(req.user.id, apiCallCount);
    
    if (!isProduction) {
      console.log(`User ${req.user.id} made ${apiCallCount} API calls for playlists`);
    }
    
    res.json({ 
      playlists,
      quota: quotaTracker.getQuotaStatus(req.user.id)
    });
  } catch (err) {
    console.error('Error fetching playlists:', err.response ? err.response.data : err.message);
    res.status(err.response?.status || 500).json({ error: sanitizeError(err) });
  }
});

// Get tracks for a playlist
app.get('/api/playlists/:id/tracks', requireAuth, checkUserApiQuota, apiLimiter, async (req, res) => {
  const playlistId = req.params.id;
  
  // Validate playlist ID
  if (!isValidSpotifyId(playlistId)) {
    return res.status(400).json({ error: 'Invalid playlist ID' });
  }
  
  try {
    const tracks = [];
    let url = `https://api.spotify.com/v1/playlists/${playlistId}/tracks?limit=100`;
    let apiCallCount = 0;
    
    while (url) {
      const response = await axios.get(url, {
        headers: { Authorization: `Bearer ${req.user.access_token}` }
      });
      apiCallCount++;
      
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
    
    // Track API usage
    quotaTracker.incrementApiCalls(req.user.id, apiCallCount);
    
    if (!isProduction) {
      console.log(`User ${req.user.id} made ${apiCallCount} API calls for playlist ${playlistId}`);
    }
    
    res.json({ 
      tracks,
      quota: quotaTracker.getQuotaStatus(req.user.id)
    });
  } catch (err) {
    console.error('Error fetching tracks:', err.response ? err.response.data : err.message);
    res.status(err.response?.status || 500).json({ error: sanitizeError(err) });
  }
});

app.post(
  '/api/download',
  requireAuth,
  checkUserDownloadQuota,
  checkUserApiQuota,
  downloadLimiter,
  express.json({ limit: '1mb' }),
  async (req, res) => {
    const { selection, format } = req.body;
    if (!selection || !Array.isArray(selection) || !format) {
      return res.status(400).json({ error: 'Missing selection or format' });
    }
    
    // Count total tracks to be downloaded
    const totalTracks = selection.reduce((sum, sel) => sum + (sel.trackIds?.length || 0), 0);
    
    // Validate selection structure
    for (const sel of selection) {
      if (
        typeof sel.playlistId !== 'string' ||
        !isValidSpotifyId(sel.playlistId) ||
        !Array.isArray(sel.trackIds) ||
        sel.trackIds.length === 0 ||
        sel.trackIds.length > 10000 || // Limit to prevent abuse
        !sel.trackIds.every(id => (typeof id === 'string' && isValidSpotifyId(id)) || id === null)
      ) {
        return res.status(400).json({ error: 'Invalid selection structure' });
      }
    }
    
    try {
      // Track the download before processing (to prevent circumvention)
      quotaTracker.incrementDownloads(req.user.id, totalTracks);
      
      const { results: data, skippedTracks, apiCallCount } = await fetchPlaylistsAndTracksBatchedWithTracking(
        req.user.access_token, 
        selection, 
        1000, 
        500,
        req.user.id
      );
      
      // Track API usage from the batch operation
      quotaTracker.incrementApiCalls(req.user.id, apiCallCount);
      
      if (!isProduction) {
        console.log(`User ${req.user.id} downloaded ${totalTracks} tracks using ${apiCallCount} API calls`);
      }
      
      const { content, type } = generateFile(data, format);
      res.setHeader('Content-Disposition', `attachment; filename=spotify_export.${format}`);
      res.setHeader('Content-Type', type);
      res.setHeader('X-Skipped-Tracks', JSON.stringify(skippedTracks));
      res.setHeader('X-User-Quota', JSON.stringify(quotaTracker.getQuotaStatus(req.user.id)));
      res.send(content);
    } catch (err) {
      // Add detailed logging
      console.error('Download error:', err.response?.data || err.message, err.stack);
      res.status(500).json({ error: sanitizeError(err) });
    }
  }
);



app.get('/api/status', authLimiter, (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith('Bearer ') ? authHeader.substring(7) : null;
  const decoded = token ? verifyJWT(token) : null;
  const isAuthenticated = !!decoded;
  
  let quota = null;
  if (isAuthenticated && decoded.user_id) {
    quota = quotaTracker.getQuotaStatus(decoded.user_id);
  }
  
  res.json({
    authenticated: isAuthenticated,
    hasAccessToken: !!decoded?.access_token,
    hasRefreshToken: !!decoded?.refresh_token,
    userId: decoded?.user_id,
    quota: quota
  });
});

// Get user quota information
app.get('/api/quota', requireAuth, (req, res) => {
  const quota = quotaTracker.getQuotaStatus(req.user.id);
  res.json(quota);
});

// Public playlist endpoint (no authentication required)
app.post('/api/public-playlist', publicPlaylistLimiter, express.json({ limit: '1mb' }), async (req, res) => {
  const { playlistUrl } = req.body;

  if (!playlistUrl) {
    return res.status(400).json({ error: 'Playlist URL is required' });
  }

  // Extract and validate playlist ID
  const playlistId = extractPlaylistId(playlistUrl);
  if (!playlistId || !isValidPlaylistId(playlistId)) {
    return res.status(400).json({ 
      error: 'Invalid playlist URL. Please provide a valid Spotify playlist link.' 
    });
  }

  try {
    // Get client credentials token for public API access
    const clientToken = await getClientCredentialsToken();

    // Fetch playlist metadata
    const playlistResponse = await axios.get(`https://api.spotify.com/v1/playlists/${playlistId}`, {
      headers: { Authorization: `Bearer ${clientToken}` }
    });

    const playlist = playlistResponse.data;

    // Check if playlist is public
    if (!playlist.public) {
      return res.status(403).json({ 
        error: 'This playlist is private and cannot be accessed without authentication.' 
      });
    }

    // Fetch all tracks for this playlist (handle pagination)
    let tracks = [];
    let url = `https://api.spotify.com/v1/playlists/${playlistId}/tracks?limit=100`;
    
    while (url) {
      const tracksResponse = await axios.get(url, {
        headers: { Authorization: `Bearer ${clientToken}` }
      });
      
      const trackItems = tracksResponse.data.items
        .map(item => item.track)
        .filter(track => track && track.id) // Filter out null tracks
        .map(track => ({
          id: track.id,
          title: track.name,
          artists: (track.artists || []).map(a => a.name)
        }));
      
      tracks = tracks.concat(trackItems);
      url = tracksResponse.data.next;
    }

    res.json({
      playlist: {
        id: playlist.id,
        name: playlist.name,
        description: playlist.description,
        owner: playlist.owner.display_name,
        public: playlist.public,
        trackCount: tracks.length
      },
      tracks
    });

  } catch (err) {
    console.error('Error fetching public playlist:', err.response?.data || err.message);
    
    if (err.response?.status === 404) {
      return res.status(404).json({ 
        error: 'Playlist not found. Please check the URL and try again.' 
      });
    } else if (err.response?.status === 403) {
      return res.status(403).json({ 
        error: 'This playlist is private and cannot be accessed without authentication.' 
      });
    } else if (err.response?.status >= 500) {
      return res.status(503).json({ 
        error: 'Spotify service is temporarily unavailable. Please try again later.' 
      });
    } else {
      return res.status(500).json({ 
        error: 'Failed to fetch playlist. Please try again.' 
      });
    }
  }
});

// Public playlist download endpoint
app.post('/api/public-playlist/download', publicPlaylistLimiter, express.json({ limit: '1mb' }), async (req, res) => {
  const { playlistUrl, selectedTrackIds, format } = req.body;

  if (!playlistUrl || !selectedTrackIds || !Array.isArray(selectedTrackIds) || !format) {
    return res.status(400).json({ error: 'Missing required fields: playlistUrl, selectedTrackIds, format' });
  }

  // Extract and validate playlist ID
  const playlistId = extractPlaylistId(playlistUrl);
  if (!playlistId || !isValidPlaylistId(playlistId)) {
    return res.status(400).json({ 
      error: 'Invalid playlist URL. Please provide a valid Spotify playlist link.' 
    });
  }

  // Validate selected track IDs
  if (selectedTrackIds.length === 0 || selectedTrackIds.length > 10000) {
    return res.status(400).json({ error: 'Invalid number of selected tracks' });
  }

  if (!selectedTrackIds.every(id => typeof id === 'string' && isValidSpotifyId(id))) {
    return res.status(400).json({ error: 'Invalid track ID format' });
  }

  try {
    // Get client credentials token
    const clientToken = await getClientCredentialsToken();

    // Fetch playlist metadata
    const playlistResponse = await axios.get(`https://api.spotify.com/v1/playlists/${playlistId}`, {
      headers: { Authorization: `Bearer ${clientToken}` }
    });

    const playlist = playlistResponse.data;

    if (!playlist.public) {
      return res.status(403).json({ 
        error: 'This playlist is private and cannot be accessed without authentication.' 
      });
    }

    // Fetch all tracks and filter to selected ones
    let allTracks = [];
    let url = `https://api.spotify.com/v1/playlists/${playlistId}/tracks?limit=100`;
    
    while (url) {
      const tracksResponse = await axios.get(url, {
        headers: { Authorization: `Bearer ${clientToken}` }
      });
      
      const trackItems = tracksResponse.data.items
        .map(item => item.track)
        .filter(track => track && track.id)
        .map(track => ({
          id: track.id,
          title: track.name,
          artists: (track.artists || []).map(a => a.name)
        }));
      
      allTracks = allTracks.concat(trackItems);
      url = tracksResponse.data.next;
    }

    // Filter to selected tracks
    const selectedTracks = allTracks.filter(track => selectedTrackIds.includes(track.id));

    // Generate file content
    const playlistData = [{
      id: playlist.id,
      name: playlist.name,
      tracks: selectedTracks
    }];

    const { content, type } = generateFile(playlistData, format);
    
    res.setHeader('Content-Disposition', `attachment; filename=spotify_public_playlist.${format}`);
    res.setHeader('Content-Type', type);
    res.send(content);

  } catch (err) {
    console.error('Error downloading public playlist:', err.response?.data || err.message);
    
    if (err.response?.status === 404) {
      return res.status(404).json({ 
        error: 'Playlist not found. Please check the URL and try again.' 
      });
    } else if (err.response?.status === 403) {
      return res.status(403).json({ 
        error: 'This playlist is private and cannot be accessed without authentication.' 
      });
    } else {
      return res.status(500).json({ 
        error: 'Failed to download playlist. Please try again.' 
      });
    }
  }
});

// Debug quota endpoint (development only)
if (!isProduction) {
  app.get('/api/debug-quota', requireAuth, (req, res) => {
    const quota = quotaTracker.getQuotaStatus(req.user.id);
    const apiLimitOk = quotaTracker.checkApiLimit(req.user.id);
    const downloadLimitOk = quotaTracker.checkDownloadLimit(req.user.id);
    
    res.json({
      userId: req.user.id,
      quota,
      apiLimitOk,
      downloadLimitOk,
      apiCallsRemaining: quota.apiLimit - quota.apiCalls,
      downloadsRemaining: quota.downloadLimit - quota.downloads
    });
  });
}

// Handle 404 for unmatched routes
app.use((req, res) => {
  res.status(404).json({ error: 'Not Found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal Server Error' });
});

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

process.on('SIGTERM', () => {
  console.log('\nShutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});
