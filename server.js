const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
// const path = require('path'); // Not needed for API-only server

// Load environment variables
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 2092;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://3alehawhaw:7HZybRRtsEm4Sge3@cluster0.tbima.mongodb.net/';
const SERVER_DOMAIN = process.env.SERVER_DOMAIN || 'earth.bssr-nodes.com';

// Middleware
app.use(cors({
    origin: process.env.FRONTEND_URL || [
        'http://localhost:3000', 
        'http://localhost:5000', 
        'http://127.0.0.1:5500',
        'https://chimerical-travesseiro-eb586c.netlify.app',
        'https://euphonious-gingersnap-65d3e4.netlify.app'
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));
app.use(express.json());

// Connect to MongoDB
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'teacher', 'student'], default: 'student' },
    permissions: [{ type: String }],
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Schedule Schema
const scheduleSchema = new mongoose.Schema({
    day: { type: String, required: true },
    subject: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const Schedule = mongoose.model('Schedule', scheduleSchema);

// Subject Schema
const subjectSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: String,
    chapters: [{
        title: String,
        description: String,
        lessons: Number,
        duration: String,
        createdAt: { type: Date, default: Date.now }
    }],
    createdAt: { type: Date, default: Date.now }
});

const Subject = mongoose.model('Subject', subjectSchema);

// Homework Schema
const homeworkSchema = new mongoose.Schema({
    subject: { type: String, required: true },
    description: { type: String, required: true },
    date: { type: String, required: true },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    createdAt: { type: Date, default: Date.now }
});

const Homework = mongoose.model('Homework', homeworkSchema);

// Auth middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    console.log('Auth middleware - Header:', authHeader ? 'Present' : 'Missing');
    console.log('Auth middleware - Token:', token ? 'Present' : 'Missing');

    if (!token) {
        console.log('Auth middleware - No token provided');
        return res.status(401).json({ message: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.log('Auth middleware - Token verification failed:', err.message);
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        console.log('Auth middleware - Token verified for user:', user.username);
        req.user = user;
        next();
    });
};

// Check admin/teacher permissions
const requireRole = (roles) => {
    return (req, res, next) => {
        console.log('Role check - Required roles:', roles, 'User role:', req.user.role);
        if (!roles.includes(req.user.role)) {
            console.log('Role check - Access denied for role:', req.user.role);
            return res.status(403).json({ message: 'Insufficient permissions' });
        }
        console.log('Role check - Access granted');
        next();
    };
};

// Initialize default admin user
const initializeAdmin = async () => {
    try {
        // First, let's clean up any problematic indexes
        try {
            await User.collection.dropIndex('userId_1');
            console.log('Dropped problematic userId index');
        } catch (indexError) {
            // Index might not exist, that's fine
            console.log('No userId index to drop');
        }

        const adminExists = await User.findOne({ username: 'admin' });
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            const admin = new User({
                username: 'admin',
                password: hashedPassword,
                role: 'admin',
                permissions: ['all']
            });
            await admin.save();
            console.log('Default admin user created');
        }

        const teacherExists = await User.findOne({ username: 'teacher' });
        if (!teacherExists) {
            const hashedPassword = await bcrypt.hash('teacher123', 10);
            const teacher = new User({
                username: 'teacher',
                password: hashedPassword,
                role: 'teacher',
                permissions: ['schedule', 'content', 'homework']
            });
            await teacher.save();
            console.log('Default teacher user created');
        }
    } catch (error) {
        console.error('Error initializing users:', error);
        
        // If it's a duplicate key error, let's try to fix the database
        if (error.code === 11000) {
            console.log('Attempting to fix database issues...');
            try {
                // Drop the entire users collection and recreate it
                await User.collection.drop();
                console.log('Dropped users collection');
                
                // Recreate admin user
                const hashedPassword = await bcrypt.hash('admin123', 10);
                const admin = new User({
                    username: 'admin',
                    password: hashedPassword,
                    role: 'admin',
                    permissions: ['all']
                });
                await admin.save();
                console.log('Admin user recreated successfully');
                
                // Recreate teacher user
                const teacherHashedPassword = await bcrypt.hash('teacher123', 10);
                const teacher = new User({
                    username: 'teacher',
                    password: teacherHashedPassword,
                    role: 'teacher',
                    permissions: ['schedule', 'content', 'homework']
                });
                await teacher.save();
                console.log('Teacher user recreated successfully');
                
            } catch (fixError) {
                console.error('Failed to fix database:', fixError);
            }
        }
    }
};

// Initialize default subjects (empty - admin will add everything)
const initializeSubjects = async () => {
    try {
        // No default subjects - admin will create everything
        console.log('Database ready for admin to add subjects');
    } catch (error) {
        console.error('Error initializing subjects:', error);
    }
};

// Routes

// Authentication
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { userId: user._id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            role: user.role,
            username: user.username,
            permissions: user.permissions
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// User management
app.get('/api/users', authenticateToken, requireRole(['admin']), async (req, res) => {
    try {
        const users = await User.find({}, '-password');
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/users', authenticateToken, requireRole(['admin']), async (req, res) => {
    try {
        const { username, password, role, permissions } = req.body;
        
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            username,
            password: hashedPassword,
            role,
            permissions: permissions || []
        });

        await user.save();
        res.status(201).json({ message: 'User created successfully', userId: user._id });
    } catch (error) {
        console.error('Create user error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/users/:id', authenticateToken, requireRole(['admin']), async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Schedule management
app.get('/api/schedule', async (req, res) => {
    try {
        const schedule = await Schedule.find().sort({ day: 1, time: 1 });
        res.json(schedule);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/schedule', authenticateToken, requireRole(['admin', 'teacher']), async (req, res) => {
    try {
        const { day, subject } = req.body;
        
        console.log('Adding schedule item:', { day, subject });
        
        const scheduleItem = new Schedule({
            day,
            subject
        });

        await scheduleItem.save();
        console.log('Schedule item saved successfully:', scheduleItem);
        res.status(201).json({ message: 'Schedule item added successfully', scheduleItem });
    } catch (error) {
        console.error('Add schedule error:', error);
        console.error('Error details:', error.message);
        console.error('Error stack:', error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.delete('/api/schedule/:id', authenticateToken, requireRole(['admin', 'teacher']), async (req, res) => {
    try {
        await Schedule.findByIdAndDelete(req.params.id);
        res.json({ message: 'Schedule item deleted successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Subject management
app.get('/api/subjects', async (req, res) => {
    try {
        const subjects = await Subject.find();
        res.json(subjects);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/subjects', authenticateToken, requireRole(['admin', 'teacher']), async (req, res) => {
    try {
        const { name, description } = req.body;
        
        console.log('Creating subject:', { name, description });
        console.log('User:', req.user);
        
        if (!name || name.trim() === '') {
            console.log('Subject name is required');
            return res.status(400).json({ message: 'Subject name is required' });
        }
        
        const existingSubject = await Subject.findOne({ name: new RegExp(name.trim(), 'i') });
        if (existingSubject) {
            console.log('Subject already exists:', existingSubject.name);
            return res.status(400).json({ message: 'Subject already exists' });
        }

        const subject = new Subject({
            name: name.trim(),
            description: description ? description.trim() : '',
            chapters: []
        });

        await subject.save();
        console.log('Subject created successfully:', subject);
        res.status(201).json({ message: 'Subject created successfully', subject });
    } catch (error) {
        console.error('Create subject error:', error);
        console.error('Error details:', error.message);
        console.error('Error stack:', error.stack);
        if (error.code === 11000) {
            console.log('Duplicate key error - subject already exists');
            res.status(400).json({ message: 'Subject already exists', error: error.message });
        } else {
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    }
});

app.delete('/api/subjects/:id', authenticateToken, requireRole(['admin']), async (req, res) => {
    try {
        await Subject.findByIdAndDelete(req.params.id);
        res.json({ message: 'Subject deleted successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/subjects/:name', async (req, res) => {
    try {
        const subject = await Subject.findOne({ name: new RegExp(req.params.name, 'i') });
        if (!subject) {
            return res.status(404).json({ message: 'Subject not found' });
        }
        res.json(subject);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/subjects/:subjectId/chapters', authenticateToken, requireRole(['admin', 'teacher']), async (req, res) => {
    try {
        const { title, description, lessons, duration } = req.body;
        
        const subject = await Subject.findById(req.params.subjectId);
        if (!subject) {
            return res.status(404).json({ message: 'Subject not found' });
        }

        subject.chapters.push({
            title,
            description,
            lessons: parseInt(lessons),
            duration
        });

        await subject.save();
        res.status(201).json({ message: 'Chapter added successfully', subject });
    } catch (error) {
        console.error('Add chapter error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/subjects/:subjectId/chapters/:chapterId', authenticateToken, requireRole(['admin', 'teacher']), async (req, res) => {
    try {
        const subject = await Subject.findById(req.params.subjectId);
        if (!subject) {
            return res.status(404).json({ message: 'Subject not found' });
        }

        subject.chapters.id(req.params.chapterId).remove();
        await subject.save();
        res.json({ message: 'Chapter deleted successfully' });
    } catch (error) {
        console.error('Delete chapter error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Homework management
app.get('/api/homework', async (req, res) => {
    try {
        const homework = await Homework.find()
            .populate('createdBy', 'username')
            .sort({ date: 1 });
        res.json(homework);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/homework', authenticateToken, requireRole(['admin', 'teacher']), async (req, res) => {
    try {
        const { subject, description, date } = req.body;
        
        const homework = new Homework({
            subject,
            description,
            date: date,
            createdBy: req.user.userId
        });

        await homework.save();
        res.status(201).json({ message: 'Homework created successfully', homework });
    } catch (error) {
        console.error('Create homework error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/homework/:id', authenticateToken, requireRole(['admin', 'teacher']), async (req, res) => {
    try {
        await Homework.findByIdAndDelete(req.params.id);
        res.json({ message: 'Homework deleted successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Dashboard stats
app.get('/api/dashboard-stats', authenticateToken, requireRole(['admin', 'teacher']), async (req, res) => {
    try {
        const userCount = await User.countDocuments();
        const subjectCount = await Subject.countDocuments();
        const scheduleCount = await Schedule.countDocuments();
        const homeworkCount = await Homework.countDocuments();

        res.json({
            users: userCount,
            subjects: subjectCount,
            scheduleItems: scheduleCount,
            homework: homeworkCount
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'ES1 Class API Server is running',
        timestamp: new Date().toISOString()
    });
});

// Handle 404 for API routes
app.use('/api/*', (req, res) => {
    res.status(404).json({ message: 'API endpoint not found' });
});

// Handle all other routes
app.use('*', (req, res) => {
    res.status(404).json({ message: 'API server - Frontend should be hosted separately' });
});

// Initialize database and start server
const startServer = async () => {
    await initializeAdmin();
    await initializeSubjects();
    
    const server = app.listen(PORT, '0.0.0.0', () => {
        console.log('🚀 ES1 Class API Server Started!');
        console.log('========================================');
        console.log(`📡 Server running on: http://0.0.0.0:${PORT}`);
        console.log(`🌐 Public access: http://${SERVER_DOMAIN}:${PORT}`);
        console.log(`🏠 Local access: http://localhost:${PORT}`);
        console.log('========================================');
        console.log('🔐 Default Credentials:');
        console.log('   Admin: admin / admin123');
        console.log('   Teacher: teacher / teacher123');
        console.log('========================================');
        console.log('📋 API Endpoints:');
        console.log(`   Health: http://${SERVER_DOMAIN}:${PORT}/api/health`);
        console.log(`   Login: http://${SERVER_DOMAIN}:${PORT}/api/login`);
        console.log('========================================');
    });

    // Handle server errors
    server.on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
            console.error(`❌ Port ${PORT} is already in use!`);
            console.log('Try using a different port or stop the other process.');
        } else {
            console.error('❌ Server error:', err.message);
        }
    });
};

startServer();
