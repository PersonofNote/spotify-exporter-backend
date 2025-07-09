// Simple test script to verify auth flow
const axios = require('axios');

const BASE_URL = 'http://127.0.0.1:3001';

async function testAuthFlow() {
  console.log('🧪 Testing authentication flow...');
  
  try {
    // Test 1: Check if server is running
    console.log('1. Testing server health...');
    const healthResponse = await axios.get(`${BASE_URL}/health`);
    console.log('✅ Server health:', healthResponse.data);
    
    // Test 2: Check unauthenticated status
    console.log('\n2. Testing unauthenticated status...');
    const statusResponse = await axios.get(`${BASE_URL}/api/status`, {
      validateStatus: () => true, // Don't throw on rate limit
      withCredentials: true
    });
    console.log('✅ Unauthenticated status:', statusResponse.data);
    
    // Test 3: Try to access protected endpoint
    console.log('\n3. Testing protected endpoint without auth...');
    try {
      await axios.get(`${BASE_URL}/api/playlists`, { withCredentials: true });
      console.log('❌ Should have been unauthorized');
    } catch (error) {
      if (error.response?.status === 401) {
        console.log('✅ Correctly rejected unauthorized request');
      } else {
        console.log('❌ Unexpected error:', error.message);
      }
    }
    
    console.log('\n🎯 Manual test required:');
    console.log('1. Update Spotify app redirect URI to: http://127.0.0.1:5173/auth/callback');
    console.log('2. Update .env SPOTIFY_REDIRECT_URI to: http://127.0.0.1:5173/auth/callback');
    console.log('3. Start backend: npm run dev');
    console.log('4. Start frontend: cd ../frontend && npm run dev');
    console.log('5. Visit: http://127.0.0.1:5173');
    console.log('6. Click "Login with Spotify"');
    console.log('7. Complete Spotify login');
    console.log('8. Should redirect to http://127.0.0.1:5173/auth/callback');
    console.log('9. Frontend should exchange code for tokens and show authenticated state');
    console.log('');
    console.log('🐛 Debug endpoints:');
    console.log('- Cookie debug: GET http://127.0.0.1:3001/api/debug-cookies');
    console.log('- Session test: GET http://127.0.0.1:3001/api/session-test');
    console.log('- Status check: GET http://127.0.0.1:3001/api/status');
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.error('Make sure the server is running with: npm run dev');
  }
}

testAuthFlow();