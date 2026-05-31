/**
 * DeceptiWAF — lib/fakeProfile.js
 * Deterministic fake student profile generator for honeypot-trapped attackers.
 * Same claimed username always produces the same profile (seeded PRNG).
 * No real user data is ever exposed.
 */

const FIRST_NAMES_M = [
  'Aarav', 'Vivaan', 'Aditya', 'Vihaan', 'Arjun', 'Sai', 'Reyansh',
  'Ayaan', 'Krishna', 'Ishaan', 'Rohan', 'Samir', 'Karan', 'Dhruv',
  'Kabir', 'Yash', 'Aryan', 'Dev', 'Ved', 'Neel',
];
const FIRST_NAMES_F = [
  'Ananya', 'Diya', 'Saanvi', 'Aadya', 'Pari', 'Ira', 'Myra',
  'Anika', 'Navya', 'Kiara', 'Tara', 'Zara', 'Riya', 'Sara',
  'Neha', 'Priya', 'Isha', 'Meera', 'Aisha', 'Tanvi',
];
const LAST_NAMES = [
  'Mehta', 'Sharma', 'Verma', 'Gupta', 'Singh', 'Patel', 'Nair',
  'Reddy', 'Rao', 'Joshi', 'Bose', 'Khan', 'Malhotra', 'Agarwal',
  'Bhat', 'Kaul', 'Raina', 'Shah', 'Das', 'Khanna',
];

const BRANCHES = [
  { code: 'CSE',   full: 'B.Tech Computer Science' },
  { code: 'IT',    full: 'B.Tech Information Technology' },
  { code: 'ECE',   full: 'B.Tech Electronics & Communication' },
  { code: 'MECH',  full: 'B.Tech Mechanical Engineering' },
  { code: 'CIVIL', full: 'B.Tech Civil Engineering' },
];

const SECTIONS = ['A', 'B', 'C'];

const COURSES_BY_BRANCH = {
  CSE: [
    ['CSE301', 'Data Structures & Algorithms', 'Dr. A. Khan',    4],
    ['CSE305', 'Database Management Systems',  'Prof. M. Iqbal', 4],
    ['CSE310', 'Computer Networks',            'Dr. S. Raina',   3],
    ['CSE312', 'Operating Systems',            'Dr. P. Bhat',    4],
    ['CSE314', 'Theory of Computation',        'Dr. R. Bose',    3],
    ['CSE316', 'Compiler Design',              'Prof. K. Joshi', 3],
    ['HUM201', 'Technical Communication',      'Ms. F. Ansari',  2],
  ],
  IT: [
    ['IT301',  'Web Technologies',       'Dr. R. Bose',    4],
    ['IT305',  'Cloud Computing',        'Prof. S. Das',   4],
    ['IT310',  'Information Security',   'Dr. M. Khanna',  3],
    ['IT312',  'Software Engineering',   'Dr. P. Bhat',    4],
    ['IT314',  'Data Analytics',         'Prof. N. Kaul',  3],
    ['HUM201', 'Technical Communication', 'Ms. F. Ansari', 2],
  ],
  ECE: [
    ['ECE301', 'Signals & Systems',       'Dr. R. Verma',   4],
    ['ECE305', 'Analog Circuits',         'Prof. K. Joshi', 4],
    ['ECE310', 'Digital Communication',   'Dr. N. Kaul',    3],
    ['ECE312', 'Microprocessors',         'Dr. V. Shah',    4],
    ['ECE314', 'VLSI Design',             'Prof. A. Bose',  3],
    ['HUM201', 'Technical Communication', 'Ms. F. Ansari',  2],
  ],
  MECH: [
    ['MEC301', 'Thermodynamics',           'Dr. S. Bose',    4],
    ['MEC305', 'Fluid Mechanics',          'Prof. R. Das',   4],
    ['MEC310', 'Heat Transfer',            'Dr. A. Khanna',  3],
    ['MEC312', 'Machine Design',           'Dr. K. Bhat',    4],
    ['MEC314', 'Manufacturing Processes',  'Prof. M. Rao',   3],
    ['HUM201', 'Technical Communication',  'Ms. F. Ansari',  2],
  ],
  CIVIL: [
    ['CIV301', 'Structural Analysis',      'Dr. M. Bose',    4],
    ['CIV305', 'Geotechnical Engineering',  'Prof. S. Rao',  4],
    ['CIV310', 'Transportation Engineering','Dr. R. Khanna', 3],
    ['CIV312', 'Environmental Engineering', 'Dr. K. Bhat',   4],
    ['CIV314', 'Construction Management',   'Prof. A. Nair', 3],
    ['HUM201', 'Technical Communication',  'Ms. F. Ansari',  2],
  ],
};

const GRADES = ['A+', 'A', 'A', 'A', 'B+', 'B+', 'B', 'B+', 'A', 'A+'];

// ------------------------------------------------------------------
// Seeded PRNG (mulberry32) — same seed always produces the same
// sequence of "random" numbers, so generate(seed) is deterministic.
// ------------------------------------------------------------------
function hashSeed(str) {
  // Simple string hash (FNV-1a variant) → 32-bit unsigned int
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

function mulberry32(seed) {
  let a = seed;
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Make a PRNG instance from a seed string
function rngFromSeed(seedStr) {
  return mulberry32(hashSeed(seedStr));
}

// Pick from an array using a PRNG (deterministic)
function pickRng(arr, rng) { return arr[Math.floor(rng() * arr.length)]; }
function randIntRng(min, max, rng) { return Math.floor(rng() * (max - min + 1)) + min; }
function randFloatRng(min, max, decimals, rng) {
  return parseFloat((rng() * (max - min) + min).toFixed(decimals));
}

// ------------------------------------------------------------------
// Deterministic profile generator — same seed = same profile
// ------------------------------------------------------------------
function generate(seedStr) {
  const rng = rngFromSeed(seedStr || 'default');

  const isMale = rng() > 0.5;
  const firstName = isMale ? pickRng(FIRST_NAMES_M, rng) : pickRng(FIRST_NAMES_F, rng);
  const lastName = pickRng(LAST_NAMES, rng);
  const name = firstName + ' ' + lastName;
  const branch = pickRng(BRANCHES, rng);
  const section = pickRng(SECTIONS, rng);
  const semester = randIntRng(3, 7, rng);

  // Derive a username from the seed (so it stays consistent with what
  // the attacker typed, but looks like a real student ID)
  const seedBase = (seedStr || 'user').toLowerCase().replace(/[^a-z0-9]/g, '');
  const username = seedBase + randIntRng(100, 999, rng);

  // Pick 4-6 deterministic courses from the branch
  const pool = COURSES_BY_BRANCH[branch.code];
  const numCourses = randIntRng(4, Math.min(6, pool.length), rng);
  // Deterministic shuffle
  const indices = pool.map((_, i) => i);
  for (let i = indices.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [indices[i], indices[j]] = [indices[j], indices[i]];
  }
  const courses = indices.slice(0, numCourses).map((idx) => {
    const [code, title, instr, credits] = pool[idx];
    return [code, title, instr, credits, pickRng(GRADES, rng)];
  });

  return {
    role: 'honeypot',
    name: name,
    username: username,
    branch: branch.full,
    semester: semester,
    section: section,
    email: username + '@klyuniv.ac.in',
    cgpa: randFloatRng(6.50, 9.50, 2, rng),
    attendance: randIntRng(75, 98, rng),
    credits: randIntRng(100, 140, rng),
    dues: pickRng([0, 0, 0, 500, 800, 1200, 1500, 2000, 2500, 3000, 3500], rng),
    courses: courses,
  };
}

// ------------------------------------------------------------------
// Profile cache — same claimed username always returns the same profile.
// Keyed on the lowercase claimed username so "Admin" and "admin" match.
// ------------------------------------------------------------------
const profileCache = new Map();

function getOrCreate(claimedUsername) {
  const key = (claimedUsername || 'unknown').toLowerCase().trim();
  if (!profileCache.has(key)) {
    profileCache.set(key, generate(key));
  }
  return profileCache.get(key);
}

function cacheSize() { return profileCache.size; }
function clearCache() { profileCache.clear(); }

module.exports = { generate, getOrCreate, cacheSize, clearCache };
