const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();
const SALT_ROUNDS = 10;

// ==================== AUTH ROUTES ====================

// Register a new student (user)
router.post('/register', async (req, res) => {
  const pool = req.app.locals.pool;
  const { username, password, first_name, second_name, school_name, dob, class_level } = req.body;

  try {
    const existing = await pool.query('SELECT * FROM students WHERE username = $1', [username]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Username already taken' });
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    const result = await pool.query(
      'INSERT INTO students (username, password, first_name, second_name, school_name, dob, class_level) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [username, hashedPassword, first_name, second_name, school_name, dob, class_level]
    );

    res.status(201).json({ message: 'User registered', user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
router.post('/login', async (req, res) => {
  const pool = req.app.locals.pool;
  const { username, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM students WHERE username = $1', [username]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ error: 'Incorrect password' });
    }

    res.json({ message: 'Login successful', user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== STUDENT ROUTES ====================

// Create student manually (alternative to /register)
router.post('/students', async (req, res) => {
  const pool = req.app.locals.pool;
  const { first_name, second_name, school_name, dob, class_level, username, password } = req.body;

  try {
    const hashedPassword = password ? await bcrypt.hash(password, SALT_ROUNDS) : null;
    const result = await pool.query(
      'INSERT INTO students (first_name, second_name, school_name, dob, class_level, username, password) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [first_name, second_name, school_name, dob, class_level, username, hashedPassword]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get all students
router.get('/students', async (req, res) => {
  const pool = req.app.locals.pool;
  try {
    const result = await pool.query('SELECT * FROM students ORDER BY sid DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update a student
router.put('/students/:sid', async (req, res) => {
  const pool = req.app.locals.pool;
  const { sid } = req.params;
  const { first_name, second_name, school_name, dob, class_level } = req.body;

  try {
    const result = await pool.query(
      'UPDATE students SET first_name=$1, second_name=$2, school_name=$3, dob=$4, class_level=$5 WHERE sid=$6 RETURNING *',
      [first_name, second_name, school_name, dob, class_level, sid]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete a student and their courses
router.delete('/students/:sid', async (req, res) => {
  const pool = req.app.locals.pool;
  const { sid } = req.params;

  try {
    await pool.query('DELETE FROM courses WHERE sid = $1', [sid]);
    await pool.query('DELETE FROM students WHERE sid = $1', [sid]);
    res.json({ message: 'Student and their courses deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== COURSE ROUTES ====================

// Create a new course
router.post('/courses', async (req, res) => {
  const pool = req.app.locals.pool;
  const { sid, course_name, assessment, marks, date, status } = req.body;

  try {
    const result = await pool.query(
      'INSERT INTO courses (sid, course_name, assessment, marks, date, status) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [sid, course_name, assessment, marks, date, status]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get all courses for a student
router.get('/students/:sid/courses', async (req, res) => {
  const pool = req.app.locals.pool;
  const { sid } = req.params;

  try {
    const result = await pool.query('SELECT * FROM courses WHERE sid = $1 ORDER BY id DESC', [sid]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update a course
router.put('/courses/:id', async (req, res) => {
  const pool = req.app.locals.pool;
  const { id } = req.params;
  const { course_name, assessment, marks, date, status } = req.body;

  try {
    const result = await pool.query(
      'UPDATE courses SET course_name=$1, assessment=$2, marks=$3, date=$4, status=$5 WHERE id=$6 RETURNING *',
      [course_name, assessment, marks, date, status, id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete a course
router.delete('/courses/:id', async (req, res) => {
  const pool = req.app.locals.pool;
  const { id } = req.params;

  try {
    await pool.query('DELETE FROM courses WHERE id = $1', [id]);
    res.json({ message: 'Course deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
