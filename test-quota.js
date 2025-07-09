// Simple test script to verify quota system
const axios = require('axios');

const BASE_URL = 'http://127.0.0.1:3001';

async function testQuotaSystem() {
  console.log('🧪 Testing quota system...');
  
  try {
    // Test 1: Check quota endpoint exists
    console.log('1. Testing quota endpoint...');
    try {
      const response = await axios.get(`${BASE_URL}/api/quota`);
      console.log('❌ Should have been unauthorized');
    } catch (error) {
      if (error.response?.status === 401) {
        console.log('✅ Correctly requires authentication');
      } else {
        console.log('❌ Unexpected error:', error.message);
      }
    }
    
    // Test 2: Check status endpoint includes quota
    console.log('\n2. Testing status endpoint...');
    const statusResponse = await axios.get(`${BASE_URL}/api/status`);
    console.log('✅ Status response:', {
      authenticated: statusResponse.data.authenticated,
      hasQuota: !!statusResponse.data.quota
    });
    
    // Test 3: Check if quota file is created
    console.log('\n3. Testing quota file creation...');
    const fs = require('fs');
    if (fs.existsSync('./user-quotas.json')) {
      const quotas = JSON.parse(fs.readFileSync('./user-quotas.json', 'utf8'));
      console.log('✅ Quota file exists with', Object.keys(quotas).length, 'users');
    } else {
      console.log('ℹ️  Quota file will be created when first user authenticates');
    }
    
    console.log('\n🎯 To test full quota system:');
    console.log('1. Start backend: npm run dev');
    console.log('2. Start frontend: cd ../frontend && npm run dev');
    console.log('3. Visit: http://127.0.0.1:5173');
    console.log('4. Login and make API calls');
    console.log('5. Check quota display in UI');
    console.log('6. Try to exceed limits to test enforcement');
    console.log('');
    console.log('📊 Current limits:');
    console.log('- API calls: 1000 per day');
    console.log('- Downloads: 5 per day');
    console.log('- Individual request limits still apply');
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
  }
}

testQuotaSystem();