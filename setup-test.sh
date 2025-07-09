#!/bin/bash

# Setup script for testing the authentication flow

echo "🔧 Setting up test environment..."

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    cp .env.example .env
    echo "📝 Created .env file from template"
    echo "⚠️  Please edit .env with your Spotify API credentials before testing"
    echo ""
    echo "Required steps:"
    echo "1. Go to https://developer.spotify.com/dashboard/applications"
    echo "2. Create a new app (or use existing)"
    echo "3. Set redirect URI to: http://127.0.0.1:5173/auth/callback"
    echo "4. Copy Client ID and Client Secret to .env"
    echo "5. Generate a random SESSION_SECRET (32+ characters)"
    echo "6. Update SPOTIFY_REDIRECT_URI in .env to: http://127.0.0.1:5173/auth/callback"
    echo ""
    echo "Then run: ./setup-test.sh"
    exit 1
fi

# Check if required variables are set
source .env

if [ -z "$SPOTIFY_CLIENT_ID" ] || [ -z "$SPOTIFY_CLIENT_SECRET" ] || [ -z "$SESSION_SECRET" ]; then
    echo "❌ Please set SPOTIFY_CLIENT_ID, SPOTIFY_CLIENT_SECRET, and SESSION_SECRET in .env"
    exit 1
fi

echo "✅ Environment variables configured"

# Create sessions directory
mkdir -p sessions
chmod 700 sessions
echo "✅ Sessions directory created"

# Test the server
echo "🚀 Starting server test..."
node test-auth.js

echo ""
echo "🎯 Next steps:"
echo "1. Start the backend: npm run dev"
echo "2. In another terminal, start the frontend: cd ../frontend && npm run dev"
echo "3. Visit: http://127.0.0.1:5173"
echo "4. Click 'Login with Spotify'"
echo "5. Complete OAuth flow - should redirect to http://127.0.0.1:5173/auth/callback"
echo "6. Check console logs for debugging info"