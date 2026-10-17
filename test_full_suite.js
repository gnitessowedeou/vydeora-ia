/**
 * VYDEORA Automated Verification Test Suite
 * Tests A, B, C, D, and E (Backend & Session & Data Isolation & Security)
 */

const http = require('http');

const BASE_URL = 'http://localhost:3000';

function request(method, path, body = null, cookie = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method: method,
      headers: {
        'Content-Type': 'application/json'
      }
    };
    if (cookie) {
      options.headers['Cookie'] = cookie;
    }

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        let json = null;
        try {
          json = JSON.parse(data);
        } catch (e) {
          json = data;
        }
        resolve({
          status: res.statusCode,
          headers: res.headers,
          cookies: res.headers['set-cookie'] || [],
          body: json
        });
      });
    });

    req.on('error', reject);
    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

function extractSessionCookie(cookies) {
  for (const c of cookies) {
    if (c.startsWith('vydeora_session=')) {
      return c.split(';')[0];
    }
  }
  return null;
}

async function runTests() {
  console.log('=== STARTING VYDEORA MULTI-USER VERIFICATION TESTS ===\n');
  let testsPassed = 0;
  let testsFailed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`  ✅ PASS: ${message}`);
      testsPassed++;
    } else {
      console.error(`  ❌ FAIL: ${message}`);
      testsFailed++;
      throw new Error(`Assertion failed: ${message}`);
    }
  }

  try {
    // ------------------------------------------------------------------------
    // TEST A: NEW USER REGISTRATION & INITIALIZATION
    // ------------------------------------------------------------------------
    console.log('--- TEST A: NEW USER REGISTRATION & VERIFICATION ---');
    const user1Email = `creator_${Date.now()}@vydeora.com`;
    const user1Pass = 'SecurePassword123!';
    const user1Name = 'Sophie Laurent';

    // 1. Validation tests
    const invalidReg = await request('POST', '/api/auth/register', {
      email: 'not-an-email',
      password: '123'
    });
    assert(invalidReg.status === 400, 'Registration rejects invalid email format and short password');

    // 2. Successful Registration
    const regRes = await request('POST', '/api/auth/register', {
      fullName: user1Name,
      email: user1Email,
      password: user1Pass,
      termsAccepted: true
    });
    assert(regRes.status === 201, `User 1 registered with HTTP 201`);
    assert(regRes.body.user && regRes.body.user.email === user1Email, 'Returned user object matches registered email');
    assert(regRes.body.profile && regRes.body.profile.fullName === user1Name, 'Profile record created with correct name');
    
    const user1Cookie = extractSessionCookie(regRes.cookies);
    assert(user1Cookie !== null, 'Session cookie vydeora_session issued upon registration');

    // 3. Confirm Session & Exactly One Profile via /api/auth/me
    const meRes1 = await request('GET', '/api/auth/me', null, user1Cookie);
    assert(meRes1.status === 200, 'Authenticated /api/auth/me returns 200');
    assert(meRes1.body.user.email === user1Email, 'Authenticated session returns correct email');
    assert(meRes1.body.user.fullName === user1Name, 'Authenticated session returns correct name');
    assert(meRes1.body.entitlement && (meRes1.body.entitlement.credits_balance === 100 || meRes1.body.entitlement.credits === 100), 'New user receives 100 intro credits');
    assert(meRes1.body.projects.length === 0, 'New user starts with 0 projects (Empty State verified)');
    assert(meRes1.body.notifications.length === 1, 'New user receives welcome notification');
    console.log('  TEST A PASSED COMPLETELY!\n');

    // ------------------------------------------------------------------------
    // TEST B: PROFILE EDITING, PHOTO MANAGEMENT & PERSISTENCE
    // ------------------------------------------------------------------------
    console.log('--- TEST B: PROFILE EDITING & PHOTO MANAGEMENT ---');
    // 1. Update display name & preferences
    const updateProfRes = await request('PUT', '/api/user/profile', {
      fullName: 'Sophie Laurent-Dupond',
      preferredLanguage: 'fr',
      timeZone: 'Europe/Paris'
    }, user1Cookie);
    assert(updateProfRes.status === 200, 'PUT /api/user/profile returned 200');
    assert(updateProfRes.body.profile.fullName === 'Sophie Laurent-Dupond', 'Updated name confirmed in response');

    // 2. Upload Avatar Photo (1x1 transparent PNG base64)
    const samplePngBase64 = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
    const avatarUploadRes = await request('POST', '/api/user/avatar', { image: samplePngBase64 }, user1Cookie);
    assert(avatarUploadRes.status === 200, 'POST /api/user/avatar returned 200');
    assert(avatarUploadRes.body.avatarUrl && avatarUploadRes.body.avatarUrl.includes('/uploads/avatars/'), 'Avatar URL points to saved upload');

    // 3. Verify persistence on new request (simulating page refresh)
    const refreshRes = await request('GET', '/api/auth/me', null, user1Cookie);
    assert(refreshRes.body.user.fullName === 'Sophie Laurent-Dupond', 'Updated full name persisted after reload');
    assert(refreshRes.body.user.avatarUrl === avatarUploadRes.body.avatarUrl, 'Avatar URL persisted after reload');

    // 4. Update Preferences
    const prefRes = await request('PUT', '/api/user/preferences', {
      defaultFormat: '9:16',
      preferredVoiceLang: 'fr',
      creatorCategory: 'education'
    }, user1Cookie);
    assert(prefRes.status === 200, 'PUT /api/user/preferences returned 200');
    assert(prefRes.body.preferences.defaultFormat === '9:16', 'Preferences saved properly');

    console.log('  TEST B PASSED COMPLETELY!\n');

    // ------------------------------------------------------------------------
    // TEST C: LOGOUT AND PROTECTED ROUTE GUARDS
    // ------------------------------------------------------------------------
    console.log('--- TEST C: LOGOUT AND SESSION INVALIDATION ---');
    // 1. Log out
    const logoutRes = await request('POST', '/api/auth/logout', null, user1Cookie);
    assert(logoutRes.status === 200, 'POST /api/auth/logout returned 200');

    // 2. Verify protected route is now rejected (401)
    const afterLogoutMe = await request('GET', '/api/auth/me', null, user1Cookie);
    assert(afterLogoutMe.status === 401, 'Protected /api/auth/me rejects destroyed session with HTTP 401');

    // 3. Verify /app route redirects unauthenticated user
    const appRouteRes = await request('GET', '/app', null, user1Cookie);
    assert(appRouteRes.status === 302, 'GET /app redirects unauthenticated request with 302');
    assert(appRouteRes.headers.location.includes('/?auth=login'), 'Redirect target is login screen');

    // 4. Log in again with correct credentials
    const loginRes = await request('POST', '/api/auth/login', {
      email: user1Email,
      password: user1Pass
    });
    assert(loginRes.status === 200, 'POST /api/auth/login returned 200 for correct credentials');
    const user1NewCookie = extractSessionCookie(loginRes.cookies);
    assert(user1NewCookie !== null, 'New session cookie issued on login');

    // 5. Verify restored profile
    const restoredMe = await request('GET', '/api/auth/me', null, user1NewCookie);
    assert(restoredMe.body.user.fullName === 'Sophie Laurent-Dupond', 'Same profile restored after re-login');
    console.log('  TEST C PASSED COMPLETELY!\n');

    // ------------------------------------------------------------------------
    // TEST D: MULTIPLE USERS & STRICT DATA ISOLATION
    // ------------------------------------------------------------------------
    console.log('--- TEST D: MULTIPLE USERS & STRICT DATA ISOLATION ---');
    // 1. Create a project under User 1
    const projRes = await request('POST', '/api/user/projects', {
      title: 'Secret Video User 1',
      duration: '1:15',
      category: 'TikTok | Shorts'
    }, user1NewCookie);
    assert(projRes.status === 201, 'User 1 created a video project');
    const user1ProjectId = projRes.body.project.id;

    // 2. Register second independent user
    const user2Email = `independent_${Date.now()}@vydeora.com`;
    const user2Pass = 'OtherPassword789!';
    const user2Name = 'Marc Dupont';

    const regUser2 = await request('POST', '/api/auth/register', {
      fullName: user2Name,
      email: user2Email,
      password: user2Pass,
      termsAccepted: true
    });
    assert(regUser2.status === 201, 'User 2 registered successfully');
    const user2Cookie = extractSessionCookie(regUser2.cookies);

    // 3. User 2 fetches their own projects
    const user2ProjectsRes = await request('GET', '/api/user/projects', null, user2Cookie);
    assert(user2ProjectsRes.status === 200, 'User 2 retrieved their projects');
    assert(user2ProjectsRes.body.projects.length === 0, 'User 2 cannot see any projects');
    const hasUser1Project = user2ProjectsRes.body.projects.some(p => p.id === user1ProjectId);
    assert(!hasUser1Project, 'CRITICAL: User 1\'s private project is NOT visible to User 2');

    // 4. Test unauthorized deletion attempt of User 1\'s project by User 2
    const unauthDelete = await request('DELETE', `/api/user/projects/${user1ProjectId}`, null, user2Cookie);
    assert(unauthDelete.status === 404, 'CRITICAL: User 2 cannot delete User 1\'s project (404 Not Found / Unauthorized)');

    // 5. Verify User 2 has separate credits and profile
    const user2Me = await request('GET', '/api/auth/me', null, user2Cookie);
    assert(user2Me.body.user.email === user2Email, 'User 2 sees only their own email');
    assert(user2Me.body.user.fullName === user2Name, 'User 2 sees only their own name');
    assert(user2Me.body.user.avatarUrl === null, 'User 2 has their own default avatar, not User 1\'s avatar');
    assert(user2Me.body.entitlement && (user2Me.body.entitlement.credits_balance === 100 || user2Me.body.entitlement.credits === 100), 'User 2 has their own 100 credits balance');

    console.log('  TEST D PASSED COMPLETELY!\n');

    // ------------------------------------------------------------------------
    // TEST E: REGRESSION & PUBLIC / DASHBOARD ASSETS
    // ------------------------------------------------------------------------
    console.log('--- TEST E: REGRESSION & SYSTEM ASSETS ---');
    const landingRes = await request('GET', '/');
    assert(landingRes.status === 200, 'Public landing page responds with 200 OK');

    const appLoggedRes = await request('GET', '/app', null, user2Cookie);
    assert(appLoggedRes.status === 200, 'Authenticated /app responds with 200 OK');

    console.log('\n======================================================');
    console.log(`🎉 ALL TESTS PASSED! (${testsPassed} tests passed, 0 failed)`);
    console.log('======================================================');

  } catch (error) {
    console.error('\n❌ TEST SUITE FAILED:', error.message);
    process.exit(1);
  }
}

runTests();
