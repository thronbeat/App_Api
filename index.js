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

    const result = await pool.query('SELECT id, username, email FROM students WHERE id = $1', [decoded.userId]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    
    req.user = result.rows[0];
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

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
    message: 'Welcome to Student Progress Tracking API',
    version: '1.0.0',
    endpoints: {
      auth: {
        register: 'POST /api/auth/register',
        login: 'POST /api/auth/login',
        profile: 'GET /api/auth/profile'
      },
      courses: {
        create: 'POST /api/courses',
        getAll: 'GET /api/courses',
        getById: 'GET /api/courses/:id',
        update: 'PUT /api/courses/:id',
        delete: 'DELETE /api/courses/:id'
      },
      marks: {
        add: 'POST /api/courses/:courseId/marks',
        getByCourse: 'GET /api/courses/:courseId/marks',
        update: 'PUT /api/marks/:markId',
        delete: 'DELETE /api/marks/:markId'
      },
      progress: {
        getOverall: 'GET /api/progress',
        getByCourse: 'GET /api/courses/:courseId/progress'
      }
    }
  });
});

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, name } = req.body;

    if (!username || !email || !password || !name) {
      return res.status(400).json({ error: 'Username, email, password, and name are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    const existingUser = await pool.query(
      'SELECT id FROM students WHERE username = $1 OR email = $2',
      [username, email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const result = await pool.query(
      'INSERT INTO students (username, email, password, name) VALUES ($1, $2, $3, $4) RETURNING id, username, email, name, created_at',
      [username, email, hashedPassword, name]
    );

    const user = result.rows[0];
    const token = createToken({ userId: user.id });

    res.status(201).json({
      message: 'Student registered successfully',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        name: user.name,
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
      'SELECT id, username, email, password, name FROM students WHERE username = $1 OR email = $1',
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
        email: user.email,
        name: user.name
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

// Course Routes
app.post('/api/courses', authenticateToken, async (req, res) => {
  try {
    const { course_name, description, total_marks } = req.body;

    if (!course_name || !total_marks) {
      return res.status(400).json({ error: 'Course name and total marks are required' });
    }

    const result = await pool.query(
      'INSERT INTO courses (student_id, course_name, description, total_marks) VALUES ($1, $2, $3, $4) RETURNING *',
      [req.user.id, course_name, description || '', total_marks]
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

app.get('/api/courses', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const result = await pool.query(
      'SELECT * FROM courses WHERE student_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3',
      [req.user.id, limit, offset]
    );

    const countResult = await pool.query(
      'SELECT COUNT(*) FROM courses WHERE student_id = $1',
      [req.user.id]
    );
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

app.get('/api/courses/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'SELECT * FROM courses WHERE id = $1 AND student_id = $2',
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Course not found' });
    }

    res.json({ course: result.rows[0] });
  } catch (error) {
    console.error('Get course error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/courses/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { course_name, description, total_marks } = req.body;

    const result = await pool.query(
      'UPDATE courses SET course_name = $1, description = $2, total_marks = $3 WHERE id = $4 AND student_id = $5 RETURNING *',
      [course_name, description, total_marks, id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Course not found or not authorized' });
    }

    res.json({
      message: 'Course updated successfully',
      course: result.rows[0]
    });
  } catch (error) {
    console.error('Update course error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/courses/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM courses WHERE id = $1 AND student_id = $2 RETURNING id',
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Course not found or not authorized' });
    }

    res.json({ message: 'Course deleted successfully' });
  } catch (error) {
    console.error('Delete course error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Marks Routes
app.post('/api/courses/:courseId/marks', authenticateToken, async (req, res) => {
  try {
    const { courseId } = req.params;
    const { assessment_name, marks_obtained, date } = req.body;

    if (!assessment_name || !marks_obtained || !date) {
      return res.status(400).json({ error: 'Assessment name, marks obtained, and date are required' });
    }

    // Verify course belongs to student
    const courseCheck = await pool.query(
      'SELECT id FROM courses WHERE id = $1 AND student_id = $2',
      [courseId, req.user.id]
    );

    if (courseCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Course not found or not authorized' });
    }

    const result = await pool.query(
      'INSERT INTO marks (course_id, student_id, assessment_name, marks_obtained, date) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [courseId, req.user.id, assessment_name, marks_obtained, date]
    );

    res.status(201).json({
      message: 'Marks added successfully',
      mark: result.rows[0]
    });
  } catch (error) {
    console.error('Add marks error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/courses/:courseId/marks', authenticateToken, async (req, res) => {
  try {
    const { courseId } = req.params;

    const courseCheck = await pool.query(
      'SELECT id FROM courses WHERE id = $1 AND student_id = $2',
      [courseId, req.user.id]
    );

    if (courseCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Course not found or not authorized' });
    }

    const result = await pool.query(
      'SELECT * FROM marks WHERE course_id = $1 AND student_id = $2 ORDER BY date DESC',
      [courseId, req.user.id]
    );

    res.json({ marks: result.rows });
  } catch (error) {
    console.error('Get marks error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/marks/:markId', authenticateToken, async (req, res) => {
  try {
    const { markId } = req.params;
    const { assessment_name, marks_obtained, date } = req.body;

    const result = await pool.query(
      'UPDATE marks SET assessment_name = $1, marks_obtained = $2, date = $3 WHERE id = $4 AND student_id = $5 RETURNING *',
      [assessment_name, marks_obtained, date, markId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Mark not found or not authorized' });
    }

    res.json({
      message: 'Mark updated successfully',
      mark: result.rows[0]
    });
  } catch (error) {
    console.error('Update mark error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/marks/:markId', authenticateToken, async (req, res) => {
  try {
    const { markId } = req.params;

    const result = await pool.query(
      'DELETE FROM marks WHERE id = $1 AND student_id = $2 RETURNING id',
      [markId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Mark not found or not authorized' });
    }

    res.json({ message: 'Mark deleted successfully' });
  } catch (error) {
    console.error('Delete mark error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Progress Tracking Routes
app.get('/api/progress', authenticateToken, async (req, res) => {
  try {
    const courses = await pool.query(
      'SELECT id, course_name, total_marks FROM courses WHERE student_id = $1',
      [req.user.id]
    );

    const progress = await Promise.all(courses.rows.map(async (course) => {
      const marks = await pool.query(
        'SELECT SUM(marks_obtained) as total_obtained FROM marks WHERE course_id = $1 AND student_id = $2',
        [course.id, req.user.id]
      );

      const total_obtained = marks.rows[0].total_obtained || 0;
      const percentage = course.total_marks > 0 ? (total_obtained / course.total_marks) * 100 : 0;

      return {
        course_id: course.id,
        course_name: course.course_name,
        total_marks: course.total_marks,
        marks_obtained: total_obtained,
        percentage: Number(percentage.toFixed(2)),
        status: percentage >= 50 ? 'Passing' : 'Needs Improvement'
      };
    }));

    const overall = progress.reduce((acc, curr) => ({
      total_marks: acc.total_marks + curr.total_marks,
      marks_obtained: acc.marks_obtained + curr.marks_obtained,
      courses: acc.courses + 1
    }), { total_marks: 0, marks_obtained: 0, courses: 0 });

    const overall_percentage = overall.total_marks > 0 ? 
      (overall.marks_obtained / overall.total_marks) * 100 : 0;

    res.json({
      overall: {
        total_courses: overall.courses,
        total_marks: overall.total_marks,
        marks_obtained: overall.marks_obtained,
        percentage: Number(overall_percentage.toFixed(2)),
        status: overall_percentage >= 50 ? 'Passing' : 'Needs Improvement'
      },
      courses: progress
    });
  } catch (error) {
    console.error('Get progress error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/courses/:courseId/progress', authenticateToken, async (req, res) => {
  try {
    const { courseId } = req.params;

    const course = await pool.query(
      'SELECT id, course_name, total_marks FROM courses WHERE id = $1 AND student_id = $2',
      [courseId, req.user.id]
    );

    if (course.rows.length === 0) {
      return res.status(404).json({ error: 'Course not found or not authorized' });
    }

    const marks = await pool.query(
      'SELECT * FROM marks WHERE course_id = $1 AND student_id = $2 ORDER BY date DESC',
      [courseId, req.user.id]
    );

    const total_obtained = marks.rows.reduce((sum, mark) => sum + mark.marks_obtained, 0);
    const percentage = course.rows[0].total_marks > 0 ? 
      (total_obtained / course.rows[0].total_marks) * 100 : 0;

    res.json({
      course: {
        id: course.rows[0].id,
        name: course.rows[0].course_name,
        total_marks: course.rows[0].total_marks,
        marks_obtained: total_obtained,
        percentage: Number(percentage.toFixed(2)),
        status: percentage >= 50 ? 'Passing' : 'Needs Improvement'
      },
      assessments: marks.rows
    });
  } catch (error) {
    console.error('Get course progress error:', error);
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
