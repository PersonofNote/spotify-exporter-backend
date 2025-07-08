#!/bin/bash

# Spotify Collect Backend Deployment Script

set -e

echo "🚀 Starting Spotify Collect Backend Deployment..."

# Check if .env exists
if [ ! -f .env ]; then
    echo "❌ Error: .env file not found!"
    echo "Please copy .env.example to .env and configure your environment variables."
    exit 1
fi

# Check required environment variables
source .env
required_vars=("SPOTIFY_CLIENT_ID" "SPOTIFY_CLIENT_SECRET" "SPOTIFY_REDIRECT_URI" "SESSION_SECRET")

for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
        echo "❌ Error: $var is not set in .env file"
        exit 1
    fi
done

# Check if NODE_ENV is set to production
if [ "$NODE_ENV" = "production" ]; then
    echo "🔒 Production mode detected"
    
    # Check FRONTEND_URL for production
    if [ -z "$FRONTEND_URL" ]; then
        echo "❌ Error: FRONTEND_URL must be set in production"
        exit 1
    fi
    
    # Check if FRONTEND_URL is HTTPS
    if [[ ! "$FRONTEND_URL" =~ ^https:// ]]; then
        echo "❌ Error: FRONTEND_URL must use HTTPS in production"
        exit 1
    fi
    
    echo "✅ Production environment validated"
else
    echo "🛠️  Development mode detected"
fi

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Check syntax
echo "🔍 Checking syntax..."
node -c index.js

# Create sessions directory if it doesn't exist
mkdir -p sessions

# Set appropriate permissions for sessions directory
chmod 700 sessions

echo "✅ Backend deployment completed successfully!"
echo ""
echo "📝 To start the server:"
echo "  Development: npm run dev"
echo "  Production:  npm start"
echo ""
echo "🌐 Server will be available at: http://localhost:${PORT:-3001}"
echo "🔧 Health check endpoint: http://localhost:${PORT:-3001}/health"