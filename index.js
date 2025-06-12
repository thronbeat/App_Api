const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Simple JWT implementation
const createToken = (payload) => {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64');
  const payloadStr = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + 24 * 60 * 60 * 1000 })).toString('base64');
  const signature = require('crypto').createHmac('sha256', JWT_SECRET).update(`${header}.${payloadStr}`).digest('base64');
  return `${header}.${payloadStr}.${signature}`;
};

const verifyToken = (token) => {
  try {
    const [header, payload, signature] = token.split('.');
    const expectedSignature = require('crypto').createHmac('sha256', JWT_SECRET).update(`${header}.${payload}`).digest('base64');
    
    if (signature !== expectedSignature) return null;
    
    const decodedPayload = JSON.parse(Buffer.from(payload, 'base64').toString());
    if (decodedPayload.exp < Date.now()) return null;
    
    return decodedPayload;
  } catch {
    return null;
  }
};

// PostgreSQL Connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

// Test database connection
pool.connect((err, client, release) => {
  if (err) {
    console.error('Error acquiring client:', err.stack);
  } else {
    console.log('PostgreSQL connected successfully');
    release();
  }
});

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true }));

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    const result = await pool.query('SELECT id, username, email FROM users WHERE id = $1', [decoded.userId]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    
    req.user = result.rows[0];
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Database initialization




// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: 'Welcome to Node.js API',
    version: '1.0.0',
    endpoints: {
      auth: {
        register: 'POST /api/auth/register',
        login: 'POST /api/auth/login',
        profile: 'GET /api/auth/profile'
      },
      posts: {
        create: 'POST /api/posts',
        getAll: 'GET /api/posts',
        getById: 'GET /api/posts/:id',
        update: 'PUT /api/posts/:id',
        delete: 'DELETE /api/posts/:id'
      },
      students: {
        create: 'POST /api/students',
        getAll: 'GET /api/students',
        getById: 'GET /api/students/:id',
        update: 'PUT /api/students/:id',
        delete: 'DELETE /api/students/:id'
      },
      courses: {
        create: 'POST /api/courses',
        getAll: 'GET /api/courses',
        getById: 'GET /api/courses/:id',
        update: 'PUT /api/courses/:id',
        delete: 'DELETE /api/courses/:id',
        getByStudent: 'GET /api/students/:sid/courses',
        getStats: 'GET /api/courses/stats'
      }
    }
  });
});

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    const existingUser = await pool.query(
      'SELECT id FROM users WHERE username = $1 OR email = $2',
      [username, email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const result = await pool.query(
      'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email, created_at',
      [username, email, hashedPassword]
    );

    const user = result.rows[0];
    const token = createToken({ userId: user.id });

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        created_at: user.created_at
      },
      token
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const result = await pool.query(
      'SELECT id, username, email, password FROM users WHERE username = $1 OR email = $1',
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = createToken({ userId: user.id });

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      },
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/auth/profile', authenticateToken, (req, res) => {
  res.json({
    user: req.user
  });
});

// Students CRUD Routes
app.post('/api/students', authenticateToken, async (req, res) => {
  try {
    const { name, email } = req.body;

    if (!student_name) {
      return res.status(400).json({ error: 'Student name is required' });
    }

    const result = await pool.query(
      'INSERT INTO students (user_id, name, email) VALUES ($1, $2, $3) RETURNING *',
      [req.user.id, name, email]
    );

    res.status(201).json({
      message: 'Student created successfully',
      student: result.rows[0]
    });
  } catch (error) {
    console.error('Create student error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/students', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const result = await pool.query(`
      SELECT s.*, u.username as created_by
      FROM students s 
      JOIN users u ON s.user_id = u.id 
      ORDER BY s.created_at DESC 
      LIMIT $1 OFFSET $2
    `, [limit, offset]);

    const countResult = await pool.query('SELECT COUNT(*) FROM students');
    const total = parseInt(countResult.rows[0].count);

    res.json({
      students: result.rows,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get students error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get student by ID
app.get('/api/students/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(`
      SELECT s.*, u.username as created_by
      FROM students s 
      JOIN users u ON s.user_id = u.id 
      WHERE s.sid = $1
    `, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }

    res.json({ student: result.rows[0] });
  } catch (error) {
    console.error('Get student error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update student
app.put('/api/students/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, semail } = req.body;

    // Check if student exists and belongs to user
    const existingStudent = await pool.query(
      'SELECT sid FROM students WHERE sid = $1 AND user_id = $2',
      [id, req.user.id]
    );

    if (existingStudent.rows.length === 0) {
      return res.status(404).json({ error: 'Student not found or not authorized' });
    }

    const result = await pool.query(
      'UPDATE students SET name = $1, email = $2 WHERE sid = $3 RETURNING *',
      [student_name, student_email, id]
    );

    res.json({
      message: 'Student updated successfully',
      student: result.rows[0]
    });
  } catch (error) {
    console.error('Update student error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete student
app.delete('/api/students/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM students WHERE sid = $1 AND user_id = $2 RETURNING sid',
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Student not found or not authorized' });
    }

    res.json({ message: 'Student deleted successfully' });
  } catch (error) {
    console.error('Delete student error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Courses CRUD Routes
// Create course
app.post('/api/courses', authenticateToken, async (req, res) => {
  try {
    const { sid, course_name, assessment, marks, date, status, on_marks } = req.body;

    if (!sid || !course_name) {
      return res.status(400).json({ error: 'Student ID and course name are required' });
    }

    // Verify student belongs to the authenticated user
    const studentCheck = await pool.query(
      'SELECT sid FROM students WHERE sid = $1 AND user_id = $2',
      [sid, req.user.id]
    );

    if (studentCheck.rows.length === 0) {
      return res.status(403).json({ error: 'Student not found or not authorized' });
    }

    const result = await pool.query(
      'INSERT INTO courses (sid, course_name, assessment, marks, date, status, on_marks) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [sid, course_name, assessment, marks, date, status, on_marks]
    );

    res.status(201).json({
      message: 'Course created successfully',
      course: result.rows[0]
    });
  } catch (error) {
    console.error('Create course error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all courses
app.get('/api/courses', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const result = await pool.query(`
      SELECT c.*, s.name, s.email
      FROM courses c 
      JOIN students s ON c.sid = s.sid 
      WHERE s.user_id = $1
      ORDER BY c.date DESC, c.id DESC
      LIMIT $2 OFFSET $3
    `, [req.user.id, limit, offset]);

    const countResult = await pool.query(`
      SELECT COUNT(*) 
      FROM courses c 
      JOIN students s ON c.sid = s.sid 
      WHERE s.user_id = $1
    `, [req.user.id]);
    
    const total = parseInt(countResult.rows[0].count);

    res.json({
      courses: result.rows,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get courses error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get course by ID
app.get('/api/courses/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(`
      SELECT c.*, s.name, s.email
      FROM courses c 
      JOIN students s ON c.sid = s.sid 
      WHERE c.id = $1 AND s.user_id = $2
    `, [id, req.user.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Course not found' });
    }

    res.json({ course: result.rows[0] });
  } catch (error) {
    console.error('Get course error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update course
app.put('/api/courses/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { course_name, assessment, marks, date, status, on_marks } = req.body;

    // Check if course exists and belongs to user's student
    const existingCourse = await pool.query(`
      SELECT c.id 
      FROM courses c 
      JOIN students s ON c.sid = s.sid 
      WHERE c.id = $1 AND s.user_id = $2
    `, [id, req.user.id]);

    if (existingCourse.rows.length === 0) {
      return res.status(404).json({ error: 'Course not found or not authorized' });
    }

    const result = await pool.query(
      'UPDATE courses SET course_name = $1, assessment = $2, marks = $3, date = $4, status = $5, on_marks = $6 WHERE id = $7 RETURNING *',
      [course_name, assessment, marks, date, status, on_marks, id]
    );

    res.json({
      message: 'Course updated successfully',
      course: result.rows[0]
    });
  } catch (error) {
    console.error('Update course error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete course
app.delete('/api/courses/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(`
      DELETE FROM courses c
      USING students s
      WHERE c.sid = s.sid AND c.id = $1 AND s.user_id = $2
      RETURNING c.id
    `, [id, req.user.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Course not found or not authorized' });
    }

    res.json({ message: 'Course deleted successfully' });
  } catch (error) {
    console.error('Delete course error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get courses by student ID
app.get('/api/students/:sid/courses', authenticateToken, async (req, res) => {
  try {
    const { sid } = req.params;

    // Verify student belongs to the authenticated user
    const studentCheck = await pool.query(
      'SELECT sid FROM students WHERE sid = $1 AND user_id = $2',
      [sid, req.user.id]
    );

    if (studentCheck.rows.length === 0) {
      return res.status(403).json({ error: 'Student not found or not authorized' });
    }

    const result = await pool.query(`
      SELECT c.*, s.student_name, s.student_email
      FROM courses c
      JOIN students s ON c.sid = s.sid
      WHERE c.sid = $1
      ORDER BY c.date DESC, c.id DESC
    `, [sid]);

    res.json({ courses: result.rows });
  } catch (error) {
    console.error('Get student courses error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get course statistics
app.get('/api/courses/stats', authenticateToken, async (req, res) => {
  try {
    const stats = await pool.query(`
      SELECT 
        COUNT(*) as total_courses,
        COUNT(DISTINCT c.sid) as total_students_with_courses,
        AVG(CASE WHEN c.marks IS NOT NULL AND c.on_marks IS NOT NULL AND c.on_marks > 0 
            THEN (c.marks::float / c.on_marks::float) * 100 
            ELSE NULL END) as average_percentage,
        COUNT(CASE WHEN c.status = 'passed' THEN 1 END) as passed_count,
        COUNT(CASE WHEN c.status = 'failed' THEN 1 END) as failed_count
      FROM courses c
      JOIN students s ON c.sid = s.sid
      WHERE s.user_id = $1
    `, [req.user.id]);

    const coursesByName = await pool.query(`
      SELECT 
        c.course_name,
        COUNT(*) as count,
        AVG(CASE WHEN c.marks IS NOT NULL AND c.on_marks IS NOT NULL AND c.on_marks > 0 
            THEN (c.marks::float / c.on_marks::float) * 100 
            ELSE NULL END) as average_percentage
      FROM courses c
      JOIN students s ON c.sid = s.sid
      WHERE s.user_id = $1
      GROUP BY c.course_name
      ORDER BY count DESC
    `, [req.user.id]);

    res.json({
      overview: stats.rows[0],
      courseBreakdown: coursesByName.rows
    });
  } catch (error) {
    console.error('Get course stats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Posts CRUD Routes (existing code)
// Create post
app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const { title, content } = req.body;

    if (!title) {
      return res.status(400).json({ error: 'Title is required' });
    }

    const result = await pool.query(
      'INSERT INTO posts (title, content, user_id) VALUES ($1, $2, $3) RETURNING *',
      [title, content || '', req.user.id]
    );

    res.status(201).json({
      message: 'Post created successfully',
      post: result.rows[0]
    });
  } catch (error) {
    console.error('Create post error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all posts
app.get('/api/posts', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const result = await pool.query(`
      SELECT p.*, u.username 
      FROM posts p 
      JOIN users u ON p.user_id = u.id 
      ORDER BY p.created_at DESC 
      LIMIT $1 OFFSET $2
    `, [limit, offset]);

    const countResult = await pool.query('SELECT COUNT(*) FROM posts');
    const total = parseInt(countResult.rows[0].count);

    res.json({
      posts: result.rows,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get posts error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get post by ID
app.get('/api/posts/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(`
      SELECT p.*, u.username 
      FROM posts p 
      JOIN users u ON p.user_id = u.id 
      WHERE p.id = $1
    `, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Post not found' });
    }

    res.json({ post: result.rows[0] });
  } catch (error) {
    console.error('Get post error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update post
app.put('/api/posts/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, content } = req.body;

    // Check if post exists and belongs to user
    const existingPost = await pool.query(
      'SELECT id FROM posts WHERE id = $1 AND user_id = $2',
      [id, req.user.id]
    );

    if (existingPost.rows.length === 0) {
      return res.status(404).json({ error: 'Post not found or not authorized' });
    }

    const result = await pool.query(
      'UPDATE posts SET title = $1, content = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3 RETURNING *',
      [title, content, id]
    );

    res.json({
      message: 'Post updated successfully',
      post: result.rows[0]
    });
  } catch (error) {
    console.error('Update post error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete post
app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM posts WHERE id = $1 AND user_id = $2 RETURNING id',
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Post not found or not authorized' });
    }

    res.json({ message: 'Post deleted successfully' });
  } catch (error) {
    console.error('Delete post error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user's posts
app.get('/api/user/posts', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM posts WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );

    res.json({ posts: result.rows });
  } catch (error) {
    console.error('Get user posts error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Global error handler
app.use((error, req, res, next) => {
  console.error('Global error handler:', error);
  res.status(500).json({ 
    error: 'Something went wrong!',
    message: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
  });
});

// Handle 404 routes
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Route not found',
    path: req.originalUrl 
  });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
  console.log(`API docs: http://localhost:${PORT}/`);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Shutting down gracefully...');
  await pool.end();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('Shutting down gracefully...');
  await pool.end();
  process.exit(0);
});

module.exports = app;
