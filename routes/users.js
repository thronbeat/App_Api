const express = require('express');
const router = express.Router();
const pool = require('../db');

// Register a new student
router.post('/register', async (req, res) => {
  const { username, password, first_name, second_name, school_name, dob, class_level } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO students (username, password, first_name, second_name, school_name, dob, class_level)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [username, password, first_name, second_name, school_name, dob, class_level]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: 'Failed to register student' });
  }
});

// Login
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query(
      `SELECT * FROM students WHERE username = $1 AND password = $2`,
      [username, password]
    );
    if (result.rows.length > 0) {
      res.json({ message: 'Login successful', student: result.rows[0] });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get all students
router.get('/students', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM students');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch students' });
  }
});

// Update a student
router.put('/students/:sid', async (req, res) => {
  const { sid } = req.params;
  const { first_name, second_name, school_name, dob, class_level } = req.body;
  try {
    const result = await pool.query(
      `UPDATE students SET first_name = $1, second_name = $2, school_name = $3, dob = $4, class_level = $5
       WHERE sid = $6 RETURNING *`,
      [first_name, second_name, school_name, dob, class_level, sid]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update student' });
  }
});

// Delete a student
router.delete('/students/:sid', async (req, res) => {
  const { sid } = req.params;
  try {
    await pool.query('DELETE FROM students WHERE sid = $1', [sid]);
    res.json({ message: 'Student deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete student' });
  }
});

// Create a course for a student
router.post('/courses', async (req, res) => {
  const { sid, course_name, assessment, marks, date, status } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO courses (sid, course_name, assessment, marks, date, status)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [sid, course_name, assessment, marks, date, status]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to add course' });
  }
});

// Get all courses for a student
router.get('/students/:sid/courses', async (req, res) => {
  const { sid } = req.params;
  try {
    const result = await pool.query('SELECT * FROM courses WHERE sid = $1', [sid]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch courses' });
  }
});

// Update a course
router.put('/courses/:id', async (req, res) => {
  const { id } = req.params;
  const { course_name, assessment, marks, date, status } = req.body;
  try {
    const result = await pool.query(
      `UPDATE courses SET course_name = $1, assessment = $2, marks = $3, date = $4, status = $5
       WHERE id = $6 RETURNING *`,
      [course_name, assessment, marks, date, status, id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update course' });
  }
});

// Delete a course
router.delete('/courses/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM courses WHERE id = $1', [id]);
    res.json({ message: 'Course deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete course' });
  }
});

module.exports = router;
