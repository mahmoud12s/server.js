const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const archiver = require('archiver');
const axios = require('axios');

// Load environment variables
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 2092;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://3alehawhaw:7HZybRRtsEm4Sge3@cluster0.tbima.mongodb.net/';
const SERVER_DOMAIN = process.env.SERVER_DOMAIN || 'lodes1b.thteam.me';
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || 'https://discord.com/api/webhooks/1419271989889339392/YBs0zI2JvaDJ0AEYMtQJdkoEAQg4IGVyIs6BbR90COZL2FbJG5kro62g6SxwRI4Mppy1';

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        // Extract subjectId from the request URL
        const subjectId = req.params.subjectId || req.body.subjectId || 'temp';
        const uploadPath = path.join(uploadsDir, subjectId);
        
        console.log('Creating upload path:', uploadPath);
        
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
            console.log('Created directory:', uploadPath);
        }
        cb(null, uploadPath);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const filename = uniqueSuffix + path.extname(file.originalname);
        console.log('Generated filename:', filename);
        cb(null, filename);
    }
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|pdf/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (extname && mimetype) {
        return cb(null, true);
    } else {
        cb(new Error('Only images (JPEG, JPG, PNG, GIF) and PDF files are allowed'));
    }
};

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: fileFilter
});

// Middleware
// Enhanced CORS configuration with debugging
app.use((req, res, next) => {
    const origin = req.headers.origin;
    console.log('🔧 CORS Request from origin:', origin);
    
    const allowedOrigins = process.env.FRONTEND_URL ? process.env.FRONTEND_URL.split(',') : [
        'http://localhost:3000', 
        'http://localhost:5000', 
        'https://l-o-des1b.thteam.me',
        'https://l-o-des1b.thteam.me/',
        'https://lodes1b.thteam.me',
        'https://lodes1b.thteam.me/',
        'https://chimerical-travesseiro-eb586c.netlify.app',
        'https://euphonious-gingersnap-65d3e4.netlify.app'
    ];
    
    console.log('🔧 Allowed origins:', allowedOrigins);
    console.log('🔧 Origin allowed:', allowedOrigins.includes(origin));
    
    // Set CORS headers
    if (allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
    } else {
        // For development/testing - allow all origins (remove in production if needed)
        res.setHeader('Access-Control-Allow-Origin', '*');
        console.log('🔧 Using wildcard CORS for origin:', origin);
    }
    
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        console.log('🔧 Handling OPTIONS preflight request');
        res.status(200).end();
        return;
    }
    
    next();
});
app.use(express.json());

// Serve static uploads directory with proper headers
app.use('/api/uploads', express.static(uploadsDir, {
    setHeaders: (res, path, stat) => {
        const ext = path.split('.').pop().toLowerCase();
        if (ext === 'pdf') {
            res.set('Content-Type', 'application/pdf');
        } else if (['jpg', 'jpeg', 'png', 'gif'].includes(ext)) {
            res.set('Content-Type', `image/${ext === 'jpg' ? 'jpeg' : ext}`);
        }
        res.set('Access-Control-Allow-Origin', '*');
        res.set('Access-Control-Allow-Methods', 'GET');
        res.set('Cache-Control', 'public, max-age=31536000');
    }
}));

// Also serve uploads at root level for Railway compatibility
app.use('/uploads', express.static(uploadsDir, {
    setHeaders: (res, path, stat) => {
        const ext = path.split('.').pop().toLowerCase();
        if (ext === 'pdf') {
            res.set('Content-Type', 'application/pdf');
        } else if (['jpg', 'jpeg', 'png', 'gif'].includes(ext)) {
            res.set('Content-Type', `image/${ext === 'jpg' ? 'jpeg' : ext}`);
        }
        res.set('Access-Control-Allow-Origin', '*');
        res.set('Access-Control-Allow-Methods', 'GET');
        res.set('Cache-Control', 'public, max-age=31536000');
    }
}));

// Additional static serving for Railway hosting compatibility
app.use('/static/uploads', express.static(uploadsDir, {
    setHeaders: (res, path, stat) => {
        const ext = path.split('.').pop().toLowerCase();
        if (ext === 'pdf') {
            res.set('Content-Type', 'application/pdf');
        } else if (['jpg', 'jpeg', 'png', 'gif'].includes(ext)) {
            res.set('Content-Type', `image/${ext === 'jpg' ? 'jpeg' : ext}`);
        }
        res.set('Access-Control-Allow-Origin', '*');
        res.set('Access-Control-Allow-Methods', 'GET');
        res.set('Cache-Control', 'public, max-age=31536000');
    }
}));

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
    canCreateAdmin: { type: Boolean, default: false },
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
        images: [{
            filename: String,
            originalname: String,
            path: String,
            mimetype: String,
            size: Number,
            uploadedAt: { type: Date, default: Date.now },
            uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
        }],
        pdfs: [{
            filename: String,
            originalname: String,
            path: String,
            size: Number,
            uploadedAt: { type: Date, default: Date.now },
            uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
        }],
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

        // Remove old admin if exists
        await User.deleteOne({ username: 'admin' });
        
        const adminExists = await User.findOne({ username: 'mahmoud' });
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('mahmoudontop', 10);
            const admin = new User({
                username: 'mahmoud',
                password: hashedPassword,
                role: 'admin',
                permissions: ['all'],
                canCreateAdmin: true
            });
            await admin.save();
            console.log('Main admin user created: mahmoud');
        }

        const teacherExists = await User.findOne({ username: 'teacher' });
        if (!teacherExists) {
            const hashedPassword = await bcrypt.hash('teacher123', 10);
            const teacher = new User({
                username: 'teacher',
                password: hashedPassword,
                role: 'teacher',
                permissions: ['pdf_upload'], // Teachers can only upload PDFs
                canCreateAdmin: false
            });
            await teacher.save();
            console.log('Default teacher user created (PDF upload only)');
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
        
        // Check if trying to create admin
        if (role === 'admin') {
            const currentUser = await User.findById(req.user.userId);
            if (!currentUser.canCreateAdmin) {
                return res.status(403).json({ message: 'You do not have permission to create admin users' });
            }
        }
        
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            username,
            password: hashedPassword,
            role,
            permissions: permissions || [],
            canCreateAdmin: role === 'admin' ? false : undefined // New admins cannot create other admins by default
        });

        await user.save();
        
        // Trigger backup for new user creation
        await createBackup('user_created', { username, role });
        
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

// Clean up Friday entries (utility endpoint)
app.delete('/api/schedule/cleanup/friday', authenticateToken, requireRole(['admin']), async (req, res) => {
    try {
        const result = await Schedule.deleteMany({ day: { $regex: /^friday$/i } });
        res.json({ 
            message: `Deleted ${result.deletedCount} Friday schedule entries`,
            deletedCount: result.deletedCount 
        });
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
        
        // Trigger backup for new subject
        await createBackup('subject_created', { subjectName: subject.name, createdBy: req.user.username });
        
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

app.get('/api/subjects/:id', async (req, res) => {
    try {
        // Try to find by ID first, then by name for backward compatibility
        let subject;
        if (req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
            // Valid ObjectId
            subject = await Subject.findById(req.params.id);
        } else {
            // Treat as name
            subject = await Subject.findOne({ name: new RegExp(req.params.id, 'i') });
        }
        
        if (!subject) {
            return res.status(404).json({ message: 'Subject not found' });
        }
        res.json(subject);
    } catch (error) {
        console.error('Get subject error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/subjects/:subjectId/chapters', authenticateToken, requireRole(['admin', 'teacher']), async (req, res) => {
    try {
        const { title, description } = req.body;
        
        const subject = await Subject.findById(req.params.subjectId);
        if (!subject) {
            return res.status(404).json({ message: 'Subject not found' });
        }

        subject.chapters.push({
            title,
            description,
            images: [],
            pdfs: []
        });

        await subject.save();
        
        // Trigger backup for new chapter
        await createBackup('chapter_created', { 
            subjectName: subject.name, 
            chapterTitle: title,
            createdBy: req.user.username 
        });
        
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

        const chapter = subject.chapters.id(req.params.chapterId);
        if (!chapter) {
            return res.status(404).json({ message: 'Chapter not found' });
        }

        // Delete associated files
        [...chapter.images, ...chapter.pdfs].forEach(file => {
            try {
                if (fs.existsSync(file.path)) {
                    fs.unlinkSync(file.path);
                }
            } catch (err) {
                console.error('Error deleting file:', err);
            }
        });

        subject.chapters.pull({ _id: req.params.chapterId });
        await subject.save();
        
        // Trigger backup for chapter deletion
        await createBackup('chapter_deleted', { subjectName: subject.name, chapterTitle: chapter.title });
        
        res.json({ message: 'Chapter deleted successfully' });
    } catch (error) {
        console.error('Delete chapter error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// File upload endpoints
app.post('/api/subjects/:subjectId/chapters/:chapterId/upload', authenticateToken, requireRole(['admin', 'teacher']), upload.array('files', 10), async (req, res) => {
    try {
        const { subjectId, chapterId } = req.params;
        const subject = await Subject.findById(subjectId);
        
        if (!subject) {
            return res.status(404).json({ message: 'Subject not found' });
        }

        const chapter = subject.chapters.id(chapterId);
        if (!chapter) {
            return res.status(404).json({ message: 'Chapter not found' });
        }

        const user = await User.findById(req.user.userId);
        
        // Check teacher permissions
        if (user.role === 'teacher') {
            const hasOnlyPdfs = req.files.every(file => file.mimetype === 'application/pdf');
            if (!hasOnlyPdfs) {
                // Delete uploaded files if teacher tried to upload non-PDF
                req.files.forEach(file => {
                    try {
                        fs.unlinkSync(file.path);
                    } catch (err) {
                        console.error('Error deleting file:', err);
                    }
                });
                return res.status(403).json({ message: 'Teachers can only upload PDF files' });
            }
        }

        const uploadedFiles = req.files.map(file => ({
            filename: file.filename,
            originalname: file.originalname,
            path: file.path,
            mimetype: file.mimetype,
            size: file.size,
            uploadedBy: req.user.userId,
            uploadedAt: new Date()
        }));

        // Separate images and PDFs
        uploadedFiles.forEach(file => {
            if (file.mimetype.startsWith('image/')) {
                chapter.images.push(file);
            } else if (file.mimetype === 'application/pdf') {
                chapter.pdfs.push(file);
            }
        });

        await subject.save();
        
        // Trigger backup for file uploads
        await createBackup('files_uploaded', { 
            subjectName: subject.name, 
            chapterTitle: chapter.title, 
            fileCount: uploadedFiles.length,
            uploadedBy: user.username
        });

        res.json({ 
            message: 'Files uploaded successfully', 
            uploadedCount: uploadedFiles.length,
            chapter: chapter
        });
    } catch (error) {
        console.error('File upload error:', error);
        res.status(500).json({ message: 'Server error: ' + error.message });
    }
});

// Serve uploaded files
app.get('/api/files/:subjectId/:filename', (req, res) => {
    try {
        const { subjectId, filename } = req.params;
        const filePath = path.join(uploadsDir, subjectId, filename);
        
        console.log('File request:', { subjectId, filename });
        console.log('Looking for file at:', filePath);
        console.log('File exists:', fs.existsSync(filePath));
        
        if (fs.existsSync(filePath)) {
            // Set proper headers for images
            const ext = path.extname(filename).toLowerCase();
            let contentType = 'application/octet-stream';
            
            if (ext === '.jpg' || ext === '.jpeg') {
                contentType = 'image/jpeg';
            } else if (ext === '.png') {
                contentType = 'image/png';
            } else if (ext === '.gif') {
                contentType = 'image/gif';
            } else if (ext === '.pdf') {
                contentType = 'application/pdf';
            }
            
            console.log('Serving file with content type:', contentType);
            
            // Set headers
            res.set('Content-Type', contentType);
            res.set('Access-Control-Allow-Origin', '*');
            res.set('Access-Control-Allow-Methods', 'GET');
            res.set('Access-Control-Allow-Headers', 'Content-Type');
            res.set('Cache-Control', 'public, max-age=31536000'); // Cache for 1 year
            
            res.sendFile(path.resolve(filePath));
        } else {
            console.log('File not found at:', filePath);
            
            // Try alternative locations - comprehensive search
            const alternativePaths = [
                path.join(uploadsDir, filename), // Root uploads directory
                path.join(uploadsDir, 'temp', filename) // Temp directory
            ];
            
            // Search all subdirectories for the file
            try {
                const subdirs = fs.readdirSync(uploadsDir, { withFileTypes: true })
                    .filter(dirent => dirent.isDirectory())
                    .map(dirent => dirent.name);
                
                subdirs.forEach(subdir => {
                    alternativePaths.push(path.join(uploadsDir, subdir, filename));
                });
            } catch (err) {
                console.log('Error reading subdirectories:', err);
            }
            
            console.log('Trying alternative paths:', alternativePaths);
            
            // Try each path until we find the file
            for (const altPath of alternativePaths) {
                console.log('Checking:', altPath, 'exists:', fs.existsSync(altPath));
                
                if (fs.existsSync(altPath)) {
                    console.log('Found file at:', altPath);
                    
                    // Set proper content type
                    const ext = path.extname(filename).toLowerCase();
                    let contentType = 'application/octet-stream';
                    if (ext === '.jpg' || ext === '.jpeg') contentType = 'image/jpeg';
                    else if (ext === '.png') contentType = 'image/png';
                    else if (ext === '.gif') contentType = 'image/gif';
                    else if (ext === '.pdf') contentType = 'application/pdf';
                    
                    res.set('Content-Type', contentType);
                    res.set('Access-Control-Allow-Origin', '*');
                    res.set('Access-Control-Allow-Methods', 'GET');
                    res.set('Access-Control-Allow-Headers', 'Content-Type');
                    res.set('Cache-Control', 'public, max-age=31536000');
                    
                    return res.sendFile(path.resolve(altPath));
                }
            }
            
            // File not found anywhere
            res.status(404).json({ 
                message: 'File not found in any location',
                requestedPath: filePath,
                alternativePaths: alternativePaths,
                subjectId: subjectId,
                filename: filename,
                uploadsDir: uploadsDir
            });
        }
    } catch (error) {
        console.error('Error serving file:', error);
        res.status(500).json({ message: 'Server error: ' + error.message });
    }
});

// Delete specific file from chapter
app.delete('/api/subjects/:subjectId/chapters/:chapterId/files/:fileId', authenticateToken, requireRole(['admin']), async (req, res) => {
    try {
        const { subjectId, chapterId, fileId } = req.params;
        const subject = await Subject.findById(subjectId);
        
        if (!subject) {
            return res.status(404).json({ message: 'Subject not found' });
        }

        const chapter = subject.chapters.id(chapterId);
        if (!chapter) {
            return res.status(404).json({ message: 'Chapter not found' });
        }

        // Find and remove file from images or pdfs array
        let fileFound = false;
        let filePath = '';
        
        const imageIndex = chapter.images.findIndex(img => img._id.toString() === fileId);
        if (imageIndex !== -1) {
            filePath = chapter.images[imageIndex].path;
            chapter.images.splice(imageIndex, 1);
            fileFound = true;
        } else {
            const pdfIndex = chapter.pdfs.findIndex(pdf => pdf._id.toString() === fileId);
            if (pdfIndex !== -1) {
                filePath = chapter.pdfs[pdfIndex].path;
                chapter.pdfs.splice(pdfIndex, 1);
                fileFound = true;
            }
        }

        if (!fileFound) {
            return res.status(404).json({ message: 'File not found' });
        }

        // Delete physical file
        try {
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
            }
        } catch (err) {
            console.error('Error deleting physical file:', err);
        }

        await subject.save();
        res.json({ message: 'File deleted successfully' });
    } catch (error) {
        console.error('Delete file error:', error);
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

// Debug endpoint to check file structure
app.get('/api/debug/files', (req, res) => {
    try {
        const fileStructure = {};
        
        // Read uploads directory structure
        if (fs.existsSync(uploadsDir)) {
            const items = fs.readdirSync(uploadsDir, { withFileTypes: true });
            
            items.forEach(item => {
                if (item.isDirectory()) {
                    const dirPath = path.join(uploadsDir, item.name);
                    try {
                        const files = fs.readdirSync(dirPath);
                        fileStructure[item.name] = files;
                    } catch (err) {
                        fileStructure[item.name] = `Error reading directory: ${err.message}`;
                    }
                } else {
                    if (!fileStructure['_root_files']) {
                        fileStructure['_root_files'] = [];
                    }
                    fileStructure['_root_files'].push(item.name);
                }
            });
        }
        
        res.json({
            uploadsDir: uploadsDir,
            fileStructure: fileStructure,
            environment: process.env.NODE_ENV || 'development',
            platform: process.platform
        });
    } catch (error) {
        res.status(500).json({ 
            error: error.message,
            uploadsDir: uploadsDir 
        });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        uploadsDir: uploadsDir
    });
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

// Debug endpoint to check file structure
app.get('/api/debug/files', (req, res) => {
    try {
        const uploadsDirContents = fs.readdirSync(uploadsDir, { withFileTypes: true });
        const fileStructure = {};
        
        uploadsDirContents.forEach(item => {
            if (item.isDirectory()) {
                const subjectDir = path.join(uploadsDir, item.name);
                try {
                    fileStructure[item.name] = fs.readdirSync(subjectDir);
                } catch (err) {
                    fileStructure[item.name] = 'Error reading directory';
                }
            } else {
                if (!fileStructure['root_files']) fileStructure['root_files'] = [];
                fileStructure['root_files'].push(item.name);
            }
        });
        
        res.json({
            uploadsDir: uploadsDir,
            fileStructure: fileStructure,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Search and serve file by original name
app.get('/api/search-file/:originalname', async (req, res) => {
    try {
        const originalname = req.params.originalname;
        console.log('Searching for file by original name:', originalname);
        
        // Search in database for file with this original name
        const subjects = await Subject.find({
            $or: [
                { 'chapters.images.originalname': originalname },
                { 'chapters.pdfs.originalname': originalname }
            ]
        });
        
        let foundFile = null;
        let foundSubjectId = null;
        
        for (const subject of subjects) {
            for (const chapter of subject.chapters) {
                // Check images
                const imageFile = chapter.images?.find(img => img.originalname === originalname);
                if (imageFile) {
                    foundFile = imageFile;
                    foundSubjectId = subject._id;
                    break;
                }
                
                // Check PDFs
                const pdfFile = chapter.pdfs?.find(pdf => pdf.originalname === originalname);
                if (pdfFile) {
                    foundFile = pdfFile;
                    foundSubjectId = subject._id;
                    break;
                }
            }
            if (foundFile) break;
        }
        
        if (foundFile) {
            console.log('Found file in database:', foundFile);
            
            // Try to serve the file from multiple locations
            const possiblePaths = [
                path.join(uploadsDir, foundSubjectId.toString(), foundFile.filename),
                path.join(uploadsDir, foundFile.filename),
                path.join(uploadsDir, foundSubjectId.toString(), originalname),
                path.join(uploadsDir, originalname)
            ];
            
            for (const filePath of possiblePaths) {
                if (fs.existsSync(filePath)) {
                    console.log('Serving file from:', filePath);
                    
                    const ext = path.extname(originalname).toLowerCase();
                    let contentType = 'application/octet-stream';
                    if (ext === '.jpg' || ext === '.jpeg') contentType = 'image/jpeg';
                    else if (ext === '.png') contentType = 'image/png';
                    else if (ext === '.gif') contentType = 'image/gif';
                    else if (ext === '.pdf') contentType = 'application/pdf';
                    
                    res.set('Content-Type', contentType);
                    res.set('Access-Control-Allow-Origin', '*');
                    res.set('Cache-Control', 'public, max-age=31536000');
                    
                    return res.sendFile(path.resolve(filePath));
                }
            }
            
            res.status(404).json({ 
                message: 'File found in database but not on disk',
                originalname: originalname,
                filename: foundFile.filename,
                searchedPaths: possiblePaths
            });
        } else {
            res.status(404).json({ 
                message: 'File not found in database',
                originalname: originalname
            });
        }
        
    } catch (error) {
        console.error('Search file error:', error);
        res.status(500).json({ message: 'Server error: ' + error.message });
    }
});

// Railway hosting fallback endpoint
app.get('/api/railway-file/:subjectId/:filename', (req, res) => {
    try {
        const { subjectId, filename } = req.params;
        
        console.log('Railway fallback request:', { subjectId, filename });
        
        // For Railway, try absolute paths and relative paths
        const possiblePaths = [
            path.join(process.cwd(), 'uploads', subjectId, filename),
            path.join(process.cwd(), 'backend', 'uploads', subjectId, filename),
            path.join(__dirname, 'uploads', subjectId, filename),
            path.join(uploadsDir, subjectId, filename),
            path.join(uploadsDir, filename),
        ];
        
        // Also check all subdirectories
        try {
            const subdirs = fs.readdirSync(uploadsDir, { withFileTypes: true })
                .filter(dirent => dirent.isDirectory())
                .map(dirent => dirent.name);
            
            subdirs.forEach(subdir => {
                possiblePaths.push(path.join(uploadsDir, subdir, filename));
            });
        } catch (err) {
            console.log('Error reading subdirectories:', err);
        }
        
        console.log('Railway searching paths:', possiblePaths);
        
        for (const filePath of possiblePaths) {
            console.log('Railway checking:', filePath, 'exists:', fs.existsSync(filePath));
            
            if (fs.existsSync(filePath)) {
                console.log('Railway found file at:', filePath);
                
                const ext = path.extname(filename).toLowerCase();
                let contentType = 'application/octet-stream';
                
                if (ext === '.jpg' || ext === '.jpeg') contentType = 'image/jpeg';
                else if (ext === '.png') contentType = 'image/png';
                else if (ext === '.gif') contentType = 'image/gif';
                else if (ext === '.pdf') contentType = 'application/pdf';
                
                res.set('Content-Type', contentType);
                res.set('Access-Control-Allow-Origin', '*');
                res.set('Cache-Control', 'public, max-age=31536000');
                
                return res.sendFile(path.resolve(filePath));
            }
        }
        
        res.status(404).json({ 
            message: 'Railway: File not found in any location',
            searchedPaths: possiblePaths,
            cwd: process.cwd(),
            __dirname: __dirname,
            uploadsDir: uploadsDir
        });
        
    } catch (error) {
        console.error('Railway file serving error:', error);
        res.status(500).json({ message: 'Railway file serving error: ' + error.message });
    }
});

// Alternative file serving endpoint for root uploads
app.get('/api/file/:filename', (req, res) => {
    try {
        const filename = req.params.filename;
        
        // Try multiple possible locations
        const possiblePaths = [
            path.join(uploadsDir, filename), // Root uploads
            path.join(uploadsDir, 'temp', filename), // Temp directory
        ];
        
        // Also check all subject directories
        try {
            const subdirs = fs.readdirSync(uploadsDir, { withFileTypes: true })
                .filter(dirent => dirent.isDirectory())
                .map(dirent => dirent.name);
            
            subdirs.forEach(subdir => {
                possiblePaths.push(path.join(uploadsDir, subdir, filename));
            });
        } catch (err) {
            console.log('Error reading subdirectories:', err);
        }
        
        console.log('Alternative file request:', filename);
        console.log('Searching in paths:', possiblePaths);
        
        // Try each path until we find the file
        for (const filePath of possiblePaths) {
            if (fs.existsSync(filePath)) {
                console.log('Found file at:', filePath);
                
                const ext = path.extname(filename).toLowerCase();
                let contentType = 'application/octet-stream';
                
                if (ext === '.jpg' || ext === '.jpeg') contentType = 'image/jpeg';
                else if (ext === '.png') contentType = 'image/png';
                else if (ext === '.gif') contentType = 'image/gif';
                else if (ext === '.pdf') contentType = 'application/pdf';
                
                res.set('Content-Type', contentType);
                res.set('Access-Control-Allow-Origin', '*');
                res.set('Cache-Control', 'public, max-age=31536000');
                
                return res.sendFile(path.resolve(filePath));
            }
        }
        
        // If file not found anywhere
        res.status(404).json({ 
            message: 'File not found in any location', 
            filename: filename,
            searchedPaths: possiblePaths
        });
        
    } catch (error) {
        console.error('Alternative file serving error:', error);
        res.status(500).json({ message: 'Server error: ' + error.message });
    }
});

// Handle 404 for API routes
app.use('/api/*', (req, res) => {
    res.status(404).json({ message: 'API endpoint not found' });
});

// Handle all other routes
app.use('*', (req, res) => {
    res.status(404).json({ message: 'API server - Frontend should be hosted separately' });
});

// Backup System Functions
async function createBackup(eventType, eventData = {}) {
    try {
        if (!DISCORD_WEBHOOK_URL) {
            console.log('No Discord webhook URL configured, skipping backup');
            return;
        }

        const timestamp = new Date().toISOString();
        const backupDir = path.join(__dirname, 'backups');
        
        if (!fs.existsSync(backupDir)) {
            fs.mkdirSync(backupDir, { recursive: true });
        }

        const backupFileName = `backup-${eventType}-${Date.now()}.zip`;
        const backupPath = path.join(backupDir, backupFileName);

        // Create ZIP file
        const output = fs.createWriteStream(backupPath);
        const archive = archiver('zip', { zlib: { level: 9 } });

        output.on('close', async () => {
            console.log(`Backup created: ${backupFileName} (${archive.pointer()} bytes)`);
            
            // Send to Discord webhook
            await sendBackupToDiscord(backupPath, eventType, eventData);
            
            // Clean up local backup file after sending
            try {
                fs.unlinkSync(backupPath);
            } catch (err) {
                console.error('Error cleaning up backup file:', err);
            }
        });

        archive.on('error', (err) => {
            console.error('Backup archive error:', err);
        });

        archive.pipe(output);

        // Add database data
        try {
            const users = await User.find({}, '-password').lean();
            const subjects = await Subject.find().lean();
            const schedule = await Schedule.find().lean();
            const homework = await Homework.find().lean();

            const dbData = {
                timestamp,
                eventType,
                eventData,
                data: {
                    users,
                    subjects,
                    schedule,
                    homework
                }
            };

            archive.append(JSON.stringify(dbData, null, 2), { name: 'database_backup.json' });
        } catch (dbError) {
            console.error('Error backing up database:', dbError);
        }

        // Add uploaded files
        try {
            if (fs.existsSync(uploadsDir)) {
                archive.directory(uploadsDir, 'uploads');
            }
        } catch (fileError) {
            console.error('Error backing up files:', fileError);
        }

        archive.finalize();

    } catch (error) {
        console.error('Backup creation error:', error);
    }
}

async function sendBackupToDiscord(backupPath, eventType, eventData) {
    try {
        if (!DISCORD_WEBHOOK_URL) {
            console.log('No Discord webhook configured, skipping Discord upload');
            return;
        }

        const stats = fs.statSync(backupPath);
        const fileSizeInMB = (stats.size / (1024 * 1024)).toFixed(2);
        
        // Discord has a 8MB file limit for webhooks
        if (stats.size > 8 * 1024 * 1024) {
            console.log('Backup file too large for Discord webhook, skipping upload');
            return;
        }

        // Use a simpler approach without form-data dependency
        const FormData = require('form-data');
        const formData = new FormData();
        formData.append('file', fs.createReadStream(backupPath));
        
        const embedData = {
            embeds: [{
                title: '📦 ES1 Class - Backup Created',
                description: `Backup triggered by: **${eventType}**`,
                color: 0x00ff00,
                fields: [
                    {
                        name: 'File Size',
                        value: `${fileSizeInMB} MB`,
                        inline: true
                    },
                    {
                        name: 'Timestamp',
                        value: new Date().toLocaleString(),
                        inline: true
                    }
                ],
                footer: {
                    text: 'ES1 Class Management System'
                }
            }]
        };

        if (Object.keys(eventData).length > 0) {
            embedData.embeds[0].fields.push({
                name: 'Event Details',
                value: JSON.stringify(eventData, null, 2).substring(0, 1000),
                inline: false
            });
        }

        formData.append('payload_json', JSON.stringify(embedData));

        await axios.post(DISCORD_WEBHOOK_URL, formData, {
            headers: {
                ...formData.getHeaders()
            }
        });

        console.log('Backup sent to Discord successfully');
    } catch (error) {
        console.error('Error sending backup to Discord:', error.message);
        // Don't fail the main operation if backup fails
    }
}

// Migration function to fix file structure
async function migrateFileStructure() {
    try {
        console.log('Checking file structure migration...');
        
        // Get all subjects with files
        const subjects = await Subject.find({
            $or: [
                { 'chapters.images': { $exists: true, $not: { $size: 0 } } },
                { 'chapters.pdfs': { $exists: true, $not: { $size: 0 } } }
            ]
        });
        
        for (const subject of subjects) {
            const subjectDir = path.join(uploadsDir, subject._id.toString());
            
            // Create subject directory if it doesn't exist
            if (!fs.existsSync(subjectDir)) {
                fs.mkdirSync(subjectDir, { recursive: true });
                console.log('Created subject directory:', subjectDir);
            }
            
            // Check for files in wrong location and move them
            for (const chapter of subject.chapters) {
                // Check images
                if (chapter.images) {
                    for (const image of chapter.images) {
                        const wrongPath = path.join(uploadsDir, image.filename);
                        const correctPath = path.join(subjectDir, image.filename);
                        
                        if (fs.existsSync(wrongPath) && !fs.existsSync(correctPath)) {
                            fs.renameSync(wrongPath, correctPath);
                            console.log(`Moved image: ${image.filename} to correct location`);
                        }
                    }
                }
                
                // Check PDFs
                if (chapter.pdfs) {
                    for (const pdf of chapter.pdfs) {
                        const wrongPath = path.join(uploadsDir, pdf.filename);
                        const correctPath = path.join(subjectDir, pdf.filename);
                        
                        if (fs.existsSync(wrongPath) && !fs.existsSync(correctPath)) {
                            fs.renameSync(wrongPath, correctPath);
                            console.log(`Moved PDF: ${pdf.filename} to correct location`);
                        }
                    }
                }
            }
        }
        
        console.log('File structure migration completed');
    } catch (error) {
        console.error('Error during file migration:', error);
    }
}

// Initialize database and start server
const startServer = async () => {
    await initializeAdmin();
    await initializeSubjects();
    await migrateFileStructure();
    
    const server = app.listen(PORT, '0.0.0.0', () => {
        console.log('🚀 ES1 Class API Server Started!');
        console.log('========================================');
        console.log(`📡 Server running on: http://0.0.0.0:${PORT}`);
        console.log(`🌐 Public access: http://${SERVER_DOMAIN}:${PORT}`);
        console.log(`🏠 Local access: http://localhost:${PORT}`);
        console.log('========================================');
        console.log('🔐 Default Credentials:');
        console.log('   Main Admin: mahmoud / mahmoudontop');
        console.log('   Teacher: teacher / teacher123 (PDF upload only)');
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
