// End-to-end load test for the RLS demo API (run from bench.sh or directly).
//
// Mix (per iteration): 85% authenticated read, 10% authenticated write,
// 5% login.  The login share is what stresses the DB: bcrypt cost 10 runs
// inside PostgreSQL (app.login), so 5% of requests burn DB CPU on purpose.
//
// Env: BASE_URL (default http://127.0.0.1:8081), VUS (50), DURATION (30s),
//      INCLUDE_WRITES (1/0 — writes insert rows into app.documents).
import http from 'k6/http';
import { check } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:8081';
const VUS = Number(__ENV.VUS || 50);
const DURATION = __ENV.DURATION || '30s';
const INCLUDE_WRITES = (__ENV.INCLUDE_WRITES || '1') === '1';

export const options = {
  scenarios: {
    mixed: {
      executor: 'ramping-vus',
      startVUs: 5,
      stages: [
        { duration: '5s', target: VUS },
        { duration: DURATION, target: VUS },
        { duration: '5s', target: 0 },
      ],
      gracefulRampDown: '10s',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
  },
};

const USERS = [
  { email: 'alice@alpha.example', password: 'alice-password' },
  { email: 'bob@beta.example', password: 'bob-password' },
];

// One login per user before the test so the mix below is pure workload,
// not setup contention.
export function setup() {
  const tokens = {};
  for (const u of USERS) {
    const res = http.post(`${BASE_URL}/login`, JSON.stringify(u), {
      headers: { 'Content-Type': 'application/json' },
    });
    if (res.status !== 200) {
      throw new Error(`setup login failed for ${u.email}: ${res.status}`);
    }
    tokens[u.email] = res.json().token;
  }
  return tokens;
}

let writeCounter = 0;

export default function (tokens) {
  const user = USERS[(Math.random() * USERS.length) | 0];
  const bearer = { Authorization: `Bearer ${tokens[user.email]}` };
  const r = Math.random();

  if (r < 0.85) {
    // Authenticated read: session_verify + RLS-filtered SELECT.
    const res = http.get(`${BASE_URL}/documents`, { headers: bearer });
    check(res, { 'read 200': (x) => x.status === 200 });
  } else if (r < 0.95 && INCLUDE_WRITES) {
    // Authenticated write: session_verify + RLS WITH CHECK policy.
    writeCounter += 1;
    const res = http.post(
      `${BASE_URL}/documents`,
      JSON.stringify({
        title: `bench-${writeCounter}`,
        body: 'load test row',
        published: true,
      }),
      { headers: { 'Content-Type': 'application/json', ...bearer } },
    );
    check(res, { 'write 201': (x) => x.status === 201 });
  } else if (r < 0.95) {
    // Writes disabled: spend the write share on a lighter authenticated read.
    const res = http.get(`${BASE_URL}/me`, { headers: bearer });
    check(res, { 'me 200': (x) => x.status === 200 });
  } else {
    // Login: the expensive path — bcrypt cost 10 inside PostgreSQL.
    const res = http.post(`${BASE_URL}/login`, JSON.stringify(user), {
      headers: { 'Content-Type': 'application/json' },
    });
    check(res, { 'login 200': (x) => x.status === 200 });
  }
}
