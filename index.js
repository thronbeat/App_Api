const express = require('express');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto'); // Explicitly require crypto
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

app.use(helmet());
app.use(morgan('combined'));
app.use(cors({
    origin: ['http://localhost:3000', '*'], // Adjust for production
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100
}));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const connectWithRetry = async () => {
    try {
        await pool.connect();
        console.log('PostgreSQL connected successfully');
    } catch (err) {
        console.error('Database connection error:', err.stack);
        setTimeout(connectWithRetry, 5000);
    }
};
connectWithRetry();

const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;

    if (!token) return res.status(401).json({ error: 'No token provided' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const { rows } = await pool.query('SELECT id, username, email, name, created_at FROM students WHERE id = $1', [decoded.id]);
        if (rows.length === 0) return res.status(401).json({ error: 'Invalid token' });
        req.user = rows[0];
        next();
    } catch (err) {
        console.error('Token verification error:', err.message);
        res.status(401).json({ error: 'Invalid token' });
    }
};

const validateRegister = [
    body('username').trim().isLength({ min: 3, max: 50 }).withMessage('Username must be 3-50 characters'),
    body('email').isEmail().normalizeEmail().withMessage('Invalid email'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('name').trim().isLength({ min: 1, max: 100 }).withMessage('Name is required')
];

const validateLogin = [
    body('username').trim().notEmpty().withMessage('Username or email is required'),
    body('password').notEmpty().withMessage('Password is required')
];

const validateCourse = [
    body('course_name').trim().isLength({ min: 1, max: 255 }).withMessage('Course name is required'),
    body('description').optional().trim().isLength({ max: 1000 }).withMessage('Description too long'),
    body('total_marks').isInt({ min: 1 }).withMessage('Total marks must be a positive integer')
];

const validateMark = [
    body('assessment_name').trim().isLength({ min: 1, max: 255 }).withMessage('Assessment name is required'),
    body('marks_obtained').isInt({ min: 0 }).withMessage('Marks obtained must be non-negative'),
    body('date').isDate({ format: 'YYYY-MM-DD' }).withMessage('Date must be in YYYY-MM-DD format')
];

app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'OK',
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
    });
});

app.get('/', (req, res) => {
    res.status(200).json({
        message: 'Welcome to the Student Progress Tracking API',
        version: '1.0.0',
        endpoints: {
            health: '/health',
            auth: {
                register: 'POST /api/auth/register',
                login: 'POST /api/auth/login',
                profile: 'GET /api/auth/profile'
            },
            courses: {
                list: 'GET /api/courses',
                create: 'POST /api/courses',
                update: 'PUT /api/courses/:id',
                delete: 'DELETE /api/courses/:id'
            },
            marks: {
                list: 'GET /api/courses/:courseId/marks',
                create: 'POST /api/courses/:courseId/marks',
                update: 'PUT /api/marks/:id',
                delete: 'DELETE /api/marks/:id'
            },
            progress: 'GET /api/progress'
        }
    });
});

app.post('/api/auth/register', validateRegister, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
    }

    try {
        const { username, email, password, name } = req.body;

        const existingUser = await pool.query(
            'SELECT id FROM students WHERE username = $1 OR email = $2',
            [username, email]
        );
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const { rows } = await pool.query(
            'INSERT INTO students (username, email, password, name) VALUES ($1, $2, $3, $4) RETURNING id, username, email, name, created_at',
            [username, email, hashedPassword, name]
        );
        const user = rows[0];

        const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '24h' });

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
        console.error('Registration error:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/auth/login', validateLogin, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
    }

    try {
        const { username, password } = req.body;

        const { rows } = await pool.query(
            'SELECT id, username, email, name, password, created_at FROM students WHERE username = $1 OR email = $1',
            [username]
        );
        if (rows.length === 0) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }
        const user = rows[0];

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '24h' });

        res.status(200).json({
            message: 'Login successful',
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
        console.error('Login error:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/auth/profile', authenticateToken, async (req, res) => {
    try {
        res.status(200).json({
            user: {
                id: req.user.id,
                username: req.user.username,
                email: req.user.email,
                name: req.user.name,
                created_at: req.user.created_at
            }
        });
    } catch (error) {
        console.error('Profile error:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/courses', authenticateToken, async (req, res) => {
    try {
        const { rows } = await pool.query(
            'SELECT id, course_name, description, total_marks, created_at FROM courses WHERE student_id = $1 ORDER BY created_at DESC',
            [req.user.id]
        );
        res.status(200).json({ courses: rows });
    } catch (error) {
        console.error('Fetch courses error:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/courses', authenticateToken, validateCourse, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
    }

    try {
        const { course_name, description, total_marks } = req.body;
        const { rows } = await pool.query(
            'INSERT INTO courses (student_id, course_name, description, total_marks) VALUES ($1, $2, $3, $4) RETURNING id, course_name, description, total_marks, created_at',
            [req.user.id, course_name, description || '', total_marks]
        );
        res.status(201).json({ course: rows[0] });
    } catch (error) {
        console.error('Create course error:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.put('/api/courses/:id', authenticateToken, validateCourse, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
    }

    try {
        const courseId = parseInt(req.params.id);
        const { course_name, description, total_marks } = req.body;

        const { rows } = await pool.query(
            'UPDATE courses SET course_name = $1, description = $2, total_marks = $3 WHERE id = $4 AND student_id = $5 RETURNING id, course_name, description, total_marks, created_at',
            [course_name, description || '', total_marks, courseId, req.user.id]
        );
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Course not found or not authorized' });
        }
        res.status(200).json({ course: rows[0] });
    } catch (error) {
        console.error('Update course error:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/courses/:id', authenticateToken, async (req, res) => {
    try {
        const courseId = parseInt(req.params.id);
        const { rowCount } = await pool.query(
            'DELETE FROM courses WHERE id = $1 AND student_id = $2',
            [courseId, req.user.id]
        );
        if (rowCount === 0) {
            return res.status(404).json({ error: 'Course not found or not authorized' });
        }
        res.status(200).json({ message: 'Course deleted successfully' });
    } catch (error) {
        console.error('Delete course error:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/courses/:courseId/marks', authenticateToken, async (req, res) => {
    try {
        const courseId = parseInt(req.params.courseId);
        const { rows: courseRows } = await pool.query(
            'SELECT id FROM courses WHERE id = $1 AND student_id = $2',
            [courseId, req.user.id]
        );
        if (courseRows.length === 0) {
            return res.status(404).json({ error: 'Course not found or not authorized' });
        }

        const { rows } = await pool.query(
            'SELECT id, course_id, assessment_name, marks_obtained, date, created_at FROM marks WHERE course_id = $1 AND student_id = $2 ORDER BY date DESC',
            [courseId, req.user.id]
        );
        res.status(200).json({ marks: rows });
    } catch (error) {
        console.error('Fetch marks error:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/courses/:courseId/marks', authenticateToken, validateMark, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
    }

    try {
        const courseId = parseInt(req.params.courseId);
        const { assessment_name, marks_obtained, date } = req.body;

        const { rows: courseRows } = await pool.query(
            'SELECT total_marks FROM courses WHERE id = $1 AND student_id = $2',
            [courseId, req.user.id]
        );
        if (courseRows.length === 0) {
            return res.status(404).json({ error: 'Course not found or not authorized' });
        }
        if (marks_obtained > courseRows[0].total_marks) {
            return res.status(400).json({ error: 'Marks obtained cannot exceed total marks' });
        }

        const { rows } = await pool.query(
            'INSERT INTO marks (course_id, student_id, assessment_name, marks_obtained, date) VALUES ($1, $2, $3, $4, $5) RETURNING id, course_id, assessment_name, marks_obtained, date, created_at',
            [courseId, req.user.id, assessment_name, marks_obtained, date]
        );
        res.status(201).json({ mark: rows[0] });
    } catch (error) {
        console.error('Create mark error:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.put('/api/marks/:id', authenticateToken, validateMark, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
    }

    try {
        const markId = parseInt(req.params.id);
        const { assessment_name, marks_obtained, date } = req.body;

        const { rows: markRows } = await pool.query(
            'SELECT course_id FROM marks WHERE id = $1 AND student_id = $2',
            [markId, req.user.id]
        );
        if (markRows.length === 0) {
            return res.status(404).json({ error: 'Mark not found or not authorized' });
        }

        const { rows: courseRows } = await pool.query(
            'SELECT total_marks FROM courses WHERE id = $1 AND student_id = $2',
            [markRows[0].course_id, req.user.id]
        );
        if (marks_obtained > courseRows[0].total_marks) {
            return res.status(400).json({ error: 'Marks obtained cannot exceed total marks' });
        }

        const { rows } = await pool.query(
            'UPDATE marks SET assessment_name = $1, marks_obtained = $2, date = $3 WHERE id = $4 AND student_id = $5 RETURNING id, course_id, assessment_name, marks_obtained, date, created_at',
            [assessment_name, marks_obtained, date, markId, req.user.id]
        );
        res.status(200).json({ mark: rows[0] });
    } catch (error) {
        console.error('Update mark error:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/marks/:id', authenticateToken, async (req, res) => {
    try {
        const markId = parseInt(req.params.id);
        const { rowCount } = await pool.query(
            'DELETE FROM marks WHERE id = $1 AND student_id = $2',
            [markId, req.user.id]
        );
        if (rowCount === 0) {
            return res.status(404).json({ error: 'Mark not found or not authorized' });
        }
        res.status(200).json({ message: 'Mark deleted successfully' });
    } catch (error) {
        console.error('Delete mark error:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/progress', authenticateToken, async (req, res) => {
    try {
        const { rows } = await pool.query(
            `SELECT 
                c.id AS course_id,
                c.course_name,
                c.total_marks,
                COALESCE(SUM(m.marks_obtained), 0) AS marks_obtained,
                ROUND(COALESCE(SUM(m.marks_obtained) * 100.0 / NULLIF(c.total_marks, 0), 0), 2) AS percentage,
                CASE 
                    WHEN ROUND(COALESCE(SUM(m.marks_obtained) * 100.0 / NULLIF(c.total_marks, 0), 0), 2) >= 50 THEN 'Passing'
                    ELSE 'Failing'
                END AS status
            FROM courses c
            LEFT JOIN marks m ON c.id = m.course_id AND m.student_id = $1
            WHERE c.student_id = $1
            GROUP BY c.id, c.course_name, c.total_marks
            ORDER BY c.course_name`,
            [req.user.id]
        );
        res.status(200).json({ courses: rows });
    } catch (error) {
        console.error('Fetch progress error:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.use((error, req, res, next) => {
    console.error('Global error:', {
        error: error.message,
        stack: error.stack,
        path: req.path,
        method: req.method
    });
    res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/health`);
    console.log(`API docs: http://localhost:${PORT}/`);
});

process.on('SIGINT', async () => {
    console.log('Shutting down gracefully...');
    await pool.end();
    process.exit(0);
});
