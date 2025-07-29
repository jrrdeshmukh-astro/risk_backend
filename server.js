require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./db');

const app = express();

// ✅ CORS configuration
const allowedOrigins = [
  'http://localhost:3000', // for local dev
  'https://adaptive-questionnaire.vercel.app/' // replace with your actual frontend URL
];

app.use(cors({
  origin: function (origin, callback) {
    // Allow no-origin requests (like from curl/Postman)
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORS not allowed from this origin'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

const SECRET = process.env.JWT_SECRET;
const ADMIN_SECRET = process.env.ADMIN_SECRET;

// --- Login ---
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);

  if (result.rows.length === 0) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const user = result.rows[0];
  const match = await bcrypt.compare(password, user.password);

  if (!match) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, SECRET, {
    expiresIn: "1h",
  });

  res.json({
    token,
    user: {
      email: user.email,
      role: user.role,
    },
  });
});

// --- Public Signup ---
app.post('/auth/signup', async (req, res) => {
  const { email, password, name } = req.body;

  if (!email || !password || !name) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  try {
    const existing = await db.query('SELECT * FROM users WHERE email = $1', [email]);

    if (existing.rows.length > 0) {
      return res.status(409).json({ message: 'User already exists' });
    }

    const hash = await bcrypt.hash(password, 10);
    const role = 'user';

    await db.query(
      'INSERT INTO users (email, password, name, role) VALUES ($1, $2, $3, $4)',
      [email, hash, name, role]
    );

    const token = jwt.sign({ email, role }, SECRET, { expiresIn: '1h' });

    res.json({
      token,
      user: {
        email,
        role,
        name,
      },
    });
  } catch (err) {
    console.error('❌ Signup error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// --- Admin-only Create User ---
app.post('/admin/create-user', async (req, res) => {
  const { email, password, name, adminKey } = req.body;

  if (adminKey !== ADMIN_SECRET) {
    return res.status(403).json({ message: 'Forbidden' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    await db.query(
      'INSERT INTO users (email, password, name) VALUES ($1, $2, $3)',
      [email, hash, name]
    );
    res.json({ message: 'User created' });
  } catch (err) {
    console.error('Error creating user:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// --- Save Assessment Answers ---
app.post('/assessments', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: 'Missing token' });

  const token = authHeader.split(' ')[1];
  let decoded;
  try {
    decoded = jwt.verify(token, SECRET);
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }

  const { category, answers } = req.body;

  await db.query(
    'INSERT INTO assessments (user_id, category, answers) VALUES ($1, $2, $3)',
    [decoded.id, category, answers]
  );

  res.json({ message: 'Saved successfully' });
});

// --- Get Assessments for Logged-in User ---
app.get('/assessments', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: 'Missing token' });

  const token = authHeader.split(' ')[1];
  let decoded;
  try {
    decoded = jwt.verify(token, SECRET);
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }

  const result = await db.query(
    'SELECT * FROM assessments WHERE user_id = $1 ORDER BY created_at DESC',
    [decoded.id]
  );

  res.json(result.rows);
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
