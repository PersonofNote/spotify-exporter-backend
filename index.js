require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const axios = require('axios');
const querystring = require('querystring');
const { Parser: CsvParser } = require('json2csv');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const FileStore = require('session-file-store')(session);
const path = require('path');
const fs = require('fs');

// User quota tracking
class UserQuotaTracker {
  constructor() {
    this.quotaFile = './user-quotas.json';
    this.quotas = this.loadQuotas();
    this.saveInterval = setInterval(() => this.saveQuotas(), 5 * 60 * 1000); // Save every 5 minutes
  }

  loadQuotas() {
    try {
      if (fs.existsSync(this.quotaFile)) {
        const data = fs.readFileSync(this.quotaFile, 'utf8');
        return JSON.parse(data);
      }
    } catch (error) {
      console.error('Error loading quotas:', error);
    }
    return {};
  }

  saveQuotas() {
    try {
      fs.writeFileSync(this.quotaFile, JSON.stringify(this.quotas, null, 2));
    } catch (error) {
      console.error('Error saving quotas:', error);
    }
  }

  getUserQuota(userId) {
    const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
    
    if (!this.quotas[userId]) {
      this.quotas[userId] = {};
    }
    
    if (!this.quotas[userId][today]) {
      this.quotas[userId][today] = {
        apiCalls: 0,
        downloads: 0,
        downloadedTracks: 0
      };
    }
    
    return this.quotas[userId][today];
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

  // Clean up old quota data (keep last 7 days)
  cleanupOldQuotas() {
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const cutoffDate = sevenDaysAgo.toISOString().split('T')[0];

    for (const userId in this.quotas) {
      for (const date in this.quotas[userId]) {
        if (date < cutoffDate) {
          delete this.quotas[userId][date];
        }
      }
      // Remove users with no recent activity
      if (Object.keys(this.quotas[userId]).length === 0) {
        delete this.quotas[userId];
      }
    }
  }
}

const quotaTracker = new UserQuotaTracker();

// Clean up old quotas daily
setInterval(() => quotaTracker.cleanupOldQuotas(), 24 * 60 * 60 * 1000);

// Environment variable validation
const requiredEnvVars = [
  'SPOTIFY_CLIENT_ID',
  'SPOTIFY_CLIENT_SECRET', 
  'SPOTIFY_REDIRECT_URI',
  'SESSION_SECRET'
];

for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

const app = express();
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
  origin: isProduction ? FRONTEND_URL : ['http://localhost:3000', 'http://localhost:5173', 'http://127.0.0.1:5173', 'http://127.0.0.1:3001'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie'],
  exposedHeaders: ['Set-Cookie'],
  optionsSuccessStatus: 200
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());
app.use(session({
  store: new FileStore({
    path: './sessions',
    ttl: 24 * 60 * 60, // 24 hours in seconds
    reapInterval: 60 * 60 // Clean up expired sessions every hour
  }),
  secret: process.env.SESSION_SECRET,
  resave: false, // Don't save session if unmodified
  saveUninitialized: false,
  rolling: true, // Reset expiration on activity
  cookie: {
    secure: isProduction, // Use secure cookies in production
    httpOnly: true,
    sameSite: isProduction ? 'strict' : 'lax',
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    path: '/' // Ensure cookie is available for all paths
    // Don't set domain - let it default to the request domain
  },
  name: 'spotify-session'
}));

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

// Session debugging middleware (only in development)
if (!isProduction) {
  app.use((req, res, next) => {
    console.log('=== SESSION MIDDLEWARE ===');
    console.log('Request URL:', req.url);
    console.log('Session ID:', req.sessionID);
    console.log('Session exists:', !!req.session);
    console.log('Session keys:', Object.keys(req.session || {}));
    console.log('========================');
    next();
  });
}

// Auth check middleware
const requireAuth = (req, res, next) => {
  if (!isProduction) {
    console.log('=== AUTH CHECK DEBUG ===');
    console.log('URL:', req.url);
    console.log('Session ID:', req.sessionID);
    console.log('Session exists:', !!req.session);
    console.log('Has access token:', !!req.session?.access_token);
    console.log('Cookie header:', req.headers.cookie);
    console.log('========================');
  }
  
  if (!req.session?.access_token) {
    return res.status(401).json({ 
      error: 'Authentication required',
      sessionId: req.sessionID,
      hasSession: !!req.session
    });
  }
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

// User-based quota middleware
const checkUserApiQuota = (req, res, next) => {
  if (!req.session?.user_id) {
    return res.status(401).json({ error: 'User not authenticated' });
  }

  if (!quotaTracker.checkApiLimit(req.session.user_id)) {
    const status = quotaTracker.getQuotaStatus(req.session.user_id);
    if (!isProduction) {
      console.log(`API quota exceeded for user ${req.session.user_id}: ${status.apiCalls}/${status.apiLimit}`);
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
  if (!req.session?.user_id) {
    return res.status(401).json({ error: 'User not authenticated' });
  }

  if (!quotaTracker.checkDownloadLimit(req.session.user_id)) {
    const status = quotaTracker.getQuotaStatus(req.session.user_id);
    if (!isProduction) {
      console.log(`Download quota exceeded for user ${req.session.user_id}: ${status.downloads}/${status.downloadLimit}`);
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
app.get('/auth', authLimiter, (req, res) => {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: SPOTIFY_CLIENT_ID,
    scope: SCOPES,
    redirect_uri: SPOTIFY_REDIRECT_URI,
    show_dialog: 'true'
  });
  res.redirect(`https://accounts.spotify.com/authorize?${params.toString()}`);
});

// Handle token exchange from frontend (POST request with code)
app.post('/auth/exchange', authLimiter, async (req, res) => {
  const { code } = req.body;
  if (!code) {
    return res.status(400).json({ error: 'Missing authorization code' });
  }
  
  if (!isProduction) {
    console.log('=== TOKEN EXCHANGE START ===');
    console.log('Session ID before token exchange:', req.sessionID);
    console.log('Session exists:', !!req.session);
    console.log('Authorization code received from frontend');
    console.log('=============================');
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
    
    if (!isProduction) {
      console.log('Token exchange successful');
    }
    
    req.session.access_token = tokenRes.data.access_token;
    req.session.refresh_token = tokenRes.data.refresh_token;
    
    // Get user info from Spotify to store user ID
    try {
      const userResponse = await axios.get('https://api.spotify.com/v1/me', {
        headers: { Authorization: `Bearer ${tokenRes.data.access_token}` }
      });
      
      req.session.user_id = userResponse.data.id;
      
      if (!isProduction) {
        console.log('User authenticated:', userResponse.data.id);
      }
    } catch (userErr) {
      console.error('Failed to get user info:', userErr.response?.data || userErr.message);
      return res.status(500).json({ error: 'Failed to get user information' });
    }
    
    // Explicitly save the session
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
        return res.status(500).json({ error: 'Session save failed' });
      }
      if (!isProduction) {
        console.log('=== TOKEN EXCHANGE SESSION DEBUG ===');
        console.log('Session ID after save:', req.sessionID);
        console.log('Session after setting tokens:', { 
          sessionId: req.sessionID, 
          userId: req.session.user_id,
          hasAccessToken: !!req.session.access_token,
          hasRefreshToken: !!req.session.refresh_token
        });
        console.log('Cookie will be set with name:', 'spotify-session');
        console.log('Cookie path:', req.session.cookie.path);
        console.log('Cookie secure:', req.session.cookie.secure);
        console.log('Cookie httpOnly:', req.session.cookie.httpOnly);
        console.log('Cookie sameSite:', req.session.cookie.sameSite);
        console.log('====================================');
      }
      
      // Get user's quota status
      const quotaStatus = quotaTracker.getQuotaStatus(req.session.user_id);
      
      res.json({ 
        success: true, 
        authenticated: true,
        sessionId: req.sessionID,
        quota: quotaStatus
      });
    });
  } catch (err) {
    console.error('Token exchange error:', err.response?.data || err.message);
    res.status(400).json({ 
      error: 'Token exchange failed', 
      details: err.response?.data || err.message 
    });
  }
});

// Legacy callback endpoint (keep for backward compatibility)
app.get('/auth/callback', authLimiter, async (req, res) => {
  const code = req.query.code || null;
  if (!code) {
    return res.redirect(`${FRONTEND_URL}/?error=missing_code`);
  }
  
  // Redirect to frontend with the code so it can handle the exchange
  res.redirect(`${FRONTEND_URL}/auth/callback?code=${encodeURIComponent(code)}`);
});

// Get user's playlists
app.get('/api/playlists', requireAuth, checkUserApiQuota, apiLimiter, async (req, res) => {
  try {
    const playlists = [];
    let url = 'https://api.spotify.com/v1/me/playlists?limit=50';
    let apiCallCount = 0;
    
    while (url) {
      const response = await axios.get(url, {
        headers: { Authorization: `Bearer ${req.session.access_token}` }
      });
      apiCallCount++;
      
      playlists.push(...response.data.items.map(p => ({
        id: p.id,
        name: p.name
      })));
      url = response.data.next;
    }
    
    // Track API usage
    quotaTracker.incrementApiCalls(req.session.user_id, apiCallCount);
    
    if (!isProduction) {
      console.log(`User ${req.session.user_id} made ${apiCallCount} API calls for playlists`);
    }
    
    res.json({ 
      playlists,
      quota: quotaTracker.getQuotaStatus(req.session.user_id)
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
        headers: { Authorization: `Bearer ${req.session.access_token}` }
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
    quotaTracker.incrementApiCalls(req.session.user_id, apiCallCount);
    
    if (!isProduction) {
      console.log(`User ${req.session.user_id} made ${apiCallCount} API calls for playlist ${playlistId}`);
    }
    
    res.json({ 
      tracks,
      quota: quotaTracker.getQuotaStatus(req.session.user_id)
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
      quotaTracker.incrementDownloads(req.session.user_id, totalTracks);
      
      const { results: data, skippedTracks, apiCallCount } = await fetchPlaylistsAndTracksBatchedWithTracking(
        req.session.access_token, 
        selection, 
        1000, 
        500,
        req.session.user_id
      );
      
      // Track API usage from the batch operation
      quotaTracker.incrementApiCalls(req.session.user_id, apiCallCount);
      
      if (!isProduction) {
        console.log(`User ${req.session.user_id} downloaded ${totalTracks} tracks using ${apiCallCount} API calls`);
      }
      
      const { content, type } = generateFile(data, format);
      res.setHeader('Content-Disposition', `attachment; filename=spotify_export.${format}`);
      res.setHeader('Content-Type', type);
      res.setHeader('X-Skipped-Tracks', JSON.stringify(skippedTracks));
      res.setHeader('X-User-Quota', JSON.stringify(quotaTracker.getQuotaStatus(req.session.user_id)));
      res.send(content);
    } catch (err) {
      // Add detailed logging
      console.error('Download error:', err.response?.data || err.message, err.stack);
      res.status(500).json({ error: sanitizeError(err) });
    }
  }
);

// Simple session test endpoint (development only)
if (!isProduction) {
  app.get('/api/session-test', (req, res) => {
    console.log('=== SESSION TEST ===');
    console.log('Session ID:', req.sessionID);
    console.log('Session exists:', !!req.session);
    
    // Set a test value
    req.session.testValue = 'test-' + Date.now();
    console.log('Set test value:', req.session.testValue);
    
    res.json({
      sessionId: req.sessionID,
      sessionExists: !!req.session,
      testValue: req.session.testValue,
      sessionKeys: Object.keys(req.session || {})
    });
  });
}

// Test endpoint to manually check session data by session ID (development only)
if (!isProduction) {
  app.get('/api/test-session/:sessionId', (req, res) => {
    const sessionId = req.params.sessionId;
    console.log('Testing session ID:', sessionId);
    
    // Try to get session directly from store
    const sessionStore = req.sessionStore;
    sessionStore.get(sessionId, (err, session) => {
      if (err) {
        console.error('Error getting session:', err);
        return res.json({ error: 'Failed to get session', details: err.message });
      }
      console.log('Session from store:', session);
      res.json({
        sessionId,
        sessionExists: !!session,
        hasAccessToken: !!session?.access_token
      });
    });
  });

  // Cookie debugging endpoint
  app.get('/api/debug-cookies', (req, res) => {
    console.log('=== COOKIE DEBUG ===');
    console.log('Current session ID:', req.sessionID);
    console.log('Session exists:', !!req.session);
    console.log('Has access token:', !!req.session?.access_token);
    console.log('All request headers:', req.headers);
    console.log('Parsed cookies:', req.cookies);
    console.log('Raw cookie header:', req.headers.cookie);
    console.log('==================');
    
    res.json({
      sessionId: req.sessionID,
      sessionExists: !!req.session,
      hasAccessToken: !!req.session?.access_token,
      cookies: req.cookies,
      rawCookieHeader: req.headers.cookie,
      userAgent: req.headers['user-agent'],
      origin: req.headers.origin,
      referer: req.headers.referer
    });
  });
}

app.get('/api/status', authLimiter, (req, res) => {
  if (!isProduction) {
    console.log('=== STATUS ENDPOINT DEBUG ===');
    console.log('Session ID:', req.sessionID);
    console.log('Session exists:', !!req.session);
    console.log('Has access token:', !!req.session?.access_token);
    console.log('User ID:', req.session?.user_id);
    console.log('Headers:', req.headers.cookie);
    console.log('============================');
  }
  
  const isAuthenticated = !!req.session?.access_token;
  
  let quota = null;
  if (isAuthenticated && req.session.user_id) {
    quota = quotaTracker.getQuotaStatus(req.session.user_id);
  }
  
  res.json({
    authenticated: isAuthenticated,
    sessionId: req.sessionID,
    hasAccessToken: !!req.session?.access_token,
    hasRefreshToken: !!req.session?.refresh_token,
    userId: req.session?.user_id,
    quota: quota
  });
});

// Get user quota information
app.get('/api/quota', requireAuth, (req, res) => {
  const quota = quotaTracker.getQuotaStatus(req.session.user_id);
  res.json(quota);
});

// Debug quota endpoint (development only)
if (!isProduction) {
  app.get('/api/debug-quota', requireAuth, (req, res) => {
    const quota = quotaTracker.getQuotaStatus(req.session.user_id);
    const apiLimitOk = quotaTracker.checkApiLimit(req.session.user_id);
    const downloadLimitOk = quotaTracker.checkDownloadLimit(req.session.user_id);
    
    res.json({
      userId: req.session.user_id,
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
  quotaTracker.saveQuotas();
  clearInterval(quotaTracker.saveInterval);
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

process.on('SIGTERM', () => {
  console.log('\nShutting down gracefully...');
  quotaTracker.saveQuotas();
  clearInterval(quotaTracker.saveInterval);
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});
