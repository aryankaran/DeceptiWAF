/**
 * DeceptiWAF - scripts/generate-users.js
 * ------------------------------------------------------------------
 * Generates data/users.json with:
 *   - 15+ realistic student users with varied branches/CGPAs
 *   - Per-user passwords (username + "@2024") hashed with SHA-256
 *   - Admin user with socadmin123 hashed
 *   - Honeypot sentinel user
 *   - Email domain: @klyuniv.ac.in
 *
 * Run: node scripts/generate-users.js
 * ------------------------------------------------------------------
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function sha256(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

// Generate password for a student: username + "@2024"
function studentPassword(username) {
  return username + '@2024';
}

// Realistic Indian student names with varied branches
const STUDENTS = [
  { username: 'aryan',    name: 'Aryan Verma',      branch: 'CSE',  section: 'A', cgpa: 8.74, att: 92, credits: 124, dues: 2500 },
  { username: 'sucheta',  name: 'Sucheta Nair',     branch: 'CSE',  section: 'A', cgpa: 9.12, att: 96, credits: 132, dues: 0 },
  { username: 'isha',     name: 'Isha Gupta',        branch: 'IT',   section: 'B', cgpa: 8.45, att: 88, credits: 120, dues: 1500 },
  { username: 'sweet',    name: 'Sweet Patel',       branch: 'ECE',  section: 'B', cgpa: 7.92, att: 84, credits: 116, dues: 3200 },
  { username: 'shaly',    name: 'Shaly Sinha',       branch: 'CSE',  section: 'A', cgpa: 8.88, att: 90, credits: 128, dues: 800 },
  { username: 'demo1',    name: 'Demo User One',     branch: 'CSE',  section: 'A', cgpa: 8.00, att: 85, credits: 120, dues: 0 },
  { username: 'demo2',    name: 'Demo User Two',     branch: 'ECE',  section: 'B', cgpa: 8.20, att: 89, credits: 124, dues: 500 },
  { username: 'rohan',    name: 'Rohan Malhotra',    branch: 'CSE',  section: 'A', cgpa: 7.85, att: 82, credits: 118, dues: 1200 },
  { username: 'priya',    name: 'Priya Sharma',      branch: 'IT',   section: 'A', cgpa: 9.05, att: 94, credits: 130, dues: 0 },
  { username: 'kabir',    name: 'Kabir Singh',       branch: 'MECH', section: 'C', cgpa: 7.50, att: 79, credits: 112, dues: 2800 },
  { username: 'ananya',   name: 'Ananya Reddy',      branch: 'CSE',  section: 'B', cgpa: 8.92, att: 91, credits: 126, dues: 600 },
  { username: 'vivek',    name: 'Vivek Joshi',       branch: 'ECE',  section: 'A', cgpa: 8.30, att: 87, credits: 122, dues: 900 },
  { username: 'neha',     name: 'Neha Agarwal',      branch: 'IT',   section: 'B', cgpa: 8.65, att: 90, credits: 125, dues: 0 },
  { username: 'arjun',    name: 'Arjun Nair',        branch: 'CIVIL',section: 'C', cgpa: 7.75, att: 83, credits: 115, dues: 3500 },
  { username: 'zoya',     name: 'Zoya Khan',         branch: 'CSE',  section: 'A', cgpa: 9.20, att: 97, credits: 134, dues: 0 },
  { username: 'aditya',   name: 'Aditya Rao',        branch: 'MECH', section: 'B', cgpa: 8.10, att: 86, credits: 121, dues: 1100 },
];

const BRANCH_FULL = {
  CSE:   'B.Tech Computer Science',
  IT:    'B.Tech Information Technology',
  ECE:   'B.Tech Electronics & Communication',
  MECH:  'B.Tech Mechanical Engineering',
  CIVIL: 'B.Tech Civil Engineering',
};

const COURSES_BY_BRANCH = {
  CSE: [
    ['CSE301', 'Data Structures & Algorithms', 'Dr. A. Khan',    4, 'A'],
    ['CSE305', 'Database Management Systems',  'Prof. M. Iqbal', 4, 'A+'],
    ['CSE310', 'Computer Networks',            'Dr. S. Raina',   3, 'B+'],
    ['CSE312', 'Operating Systems',            'Dr. P. Bhat',    4, 'A'],
    ['HUM201', 'Technical Communication',      'Ms. F. Ansari',  2, 'A'],
  ],
  IT: [
    ['IT301',  'Web Technologies',       'Dr. R. Bose',    4, 'A'],
    ['IT305',  'Cloud Computing',        'Prof. S. Das',   4, 'A'],
    ['IT310',  'Information Security',   'Dr. M. Khanna',  3, 'A+'],
    ['IT312',  'Software Engineering',   'Dr. P. Bhat',    4, 'B+'],
    ['HUM201', 'Technical Communication', 'Ms. F. Ansari', 2, 'A'],
  ],
  ECE: [
    ['ECE301', 'Signals & Systems',       'Dr. R. Verma',   4, 'A'],
    ['ECE305', 'Analog Circuits',         'Prof. K. Joshi', 4, 'A'],
    ['ECE310', 'Digital Communication',   'Dr. N. Kaul',    3, 'B+'],
    ['ECE312', 'Microprocessors',         'Dr. V. Shah',    4, 'A'],
    ['HUM201', 'Technical Communication', 'Ms. F. Ansari',  2, 'A'],
  ],
  MECH: [
    ['MEC301', 'Thermodynamics',          'Dr. S. Bose',    4, 'B+'],
    ['MEC305', 'Fluid Mechanics',         'Prof. R. Das',   4, 'B'],
    ['MEC310', 'Heat Transfer',           'Dr. A. Khanna',  3, 'A'],
    ['MEC312', 'Machine Design',          'Dr. K. Bhat',    4, 'B+'],
    ['HUM201', 'Technical Communication', 'Ms. F. Ansari',  2, 'A'],
  ],
  CIVIL: [
    ['CIV301', 'Structural Analysis',     'Dr. M. Bose',    4, 'B'],
    ['CIV305', 'Geotechnical Engineering', 'Prof. S. Rao',  4, 'B+'],
    ['CIV310', 'Transportation Engineering','Dr. R. Khanna', 3, 'A'],
    ['CIV312', 'Environmental Engineering', 'Dr. K. Bhat',  4, 'B'],
    ['HUM201', 'Technical Communication', 'Ms. F. Ansari',  2, 'A'],
  ],
};

// Build the users object
const users = {};

// Meta keys (stripped after loading, but useful for documentation)
users._comment = 'DeceptiWAF user database. Generated by scripts/generate-users.js. Passwords are SHA-256 hashed (per-user: username@2024 for students, socadmin123 for admin).';
users._passwords = 'Students: <username>@2024 (e.g. aryan@2024). Admin: socadmin123. Stored as SHA-256 hashes in passwordHash field.';

// Students
for (const s of STUDENTS) {
  const pass = studentPassword(s.username);
  const email = s.username + '@klyuniv.ac.in';
  users[s.username] = {
    role: 'student',
    name: s.name,
    username: s.username,
    branch: BRANCH_FULL[s.branch],
    semester: 5,
    section: s.section,
    email: email,
    cgpa: s.cgpa,
    attendance: s.att,
    credits: s.credits,
    dues: s.dues,
    passwordHash: sha256(pass),
    courses: COURSES_BY_BRANCH[s.branch],
  };
}

// Admin
users.admin = {
  role: 'admin',
  name: 'SOC Administrator',
  username: 'admin',
  email: 'soc@klyuniv.ac.in',
  passwordHash: sha256('socadmin123'),
};

// Honeypot sentinel
users.__honeypot__ = {
  role: 'honeypot',
  name: 'Aarav Mehta',
  username: 'shaly',
  branch: 'B.Tech Electronics & Communication',
  semester: 5,
  section: 'B',
  email: 'aarav.m2042@klyuniv.ac.in',
  cgpa: 9.12,
  attendance: 96,
  credits: 132,
  dues: 0,
  passwordHash: sha256('honeypot_no_login'), // honeypot users never log in legitimately
  courses: COURSES_BY_BRANCH.ECE,
};

// Write to file
const outPath = path.join(__dirname, '..', 'data', 'users.json');
fs.writeFileSync(outPath, JSON.stringify(users, null, 2));

// Summary
const studentCount = STUDENTS.length;
console.log('==================================================');
console.log('  Generated data/users.json');
console.log('==================================================');
console.log(`  Students : ${studentCount}`);
console.log(`  Admin    : 1`);
console.log(`  Honeypot : 1 (sentinel)`);
console.log(`  Total    : ${studentCount + 2} users`);
console.log('');
console.log('  Password scheme: <username>@2024 (SHA-256 hashed)');
console.log('  Email domain   : @klyuniv.ac.in');
console.log('');
console.log('  Sample credentials (for demo chips):');
for (const s of STUDENTS.slice(0, 5)) {
  console.log(`    ${s.username.padEnd(10)} / ${studentPassword(s.username)}`);
}
console.log(`    admin      / socadmin123`);
console.log('==================================================');
