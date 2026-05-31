/**
 * DeceptiWAF - lib/fakeProfile.js
 * ------------------------------------------------------------------
 * Generates random fake student profiles for honeypot-trapped attackers.
 *
 * CRITICAL: Each trapped attacker sees a UNIQUE fake profile. If every
 * attacker saw the same "Shaly Sinha" data, two attackers comparing
 * notes would immediately realize it's a honeypot. Also, we NEVER use
 * real user data in the honeypot — all names, CGPAs, courses are
 * randomly generated and don't match any real student.
 * ------------------------------------------------------------------
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

function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function randInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function randFloat(min, max, decimals = 2) {
  return parseFloat((Math.random() * (max - min) + min).toFixed(decimals));
}

function generateUsername(name) {
  // Derive a username-like string from the fake name
  const parts = name.toLowerCase().split(' ');
  return parts[0] + randInt(100, 999);
}

function generate() {
  const isMale = Math.random() > 0.5;
  const firstName = isMale ? pick(FIRST_NAMES_M) : pick(FIRST_NAMES_F);
  const lastName = pick(LAST_NAMES);
  const name = firstName + ' ' + lastName;
  const branch = pick(BRANCHES);
  const section = pick(SECTIONS);
  const semester = randInt(3, 7);
  const username = generateUsername(name);

  // Pick 4-6 random courses from the branch
  const pool = COURSES_BY_BRANCH[branch.code];
  const numCourses = randInt(4, Math.min(6, pool.length));
  const shuffled = [...pool].sort(() => Math.random() - 0.5);
  const courses = shuffled.slice(0, numCourses).map(([code, title, instr, credits]) => {
    return [code, title, instr, credits, pick(GRADES)];
  });

  return {
    role: 'honeypot',
    name: name,
    username: username,
    branch: branch.full,
    semester: semester,
    section: section,
    email: username + '@klyuniv.ac.in',
    cgpa: randFloat(6.50, 9.50),
    attendance: randInt(75, 98),
    credits: randInt(100, 140),
    dues: pick([0, 0, 0, 500, 800, 1200, 1500, 2000, 2500, 3000, 3500]),
    courses: courses,
  };
}

module.exports = { generate };
