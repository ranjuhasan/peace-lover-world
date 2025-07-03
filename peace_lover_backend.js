// Peace Lover World Backend API
// Author: Peace Lover World Development Team
// Description: Node.js/Express backend for Peace Lover World website

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const morgan = require('morgan');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(helmet()); // Security headers
app.use(morgan('combined')); // Logging
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/peacelovers', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
    console.log('Connected to MongoDB');
});

// Database Schemas
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    isVerified: { type: Boolean, default: false },
    verificationToken: String,
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    createdAt: { type: Date, default: Date.now },
    lastLogin: Date,
    profile: {
        bio: String,
        location: String,
        interests: [String],
        avatar: String
    }
});

const messageSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    subject: { type: String, default: 'Peace Message' },
    message: { type: String, required: true },
    status: { type: String, enum: ['pending', 'read', 'replied'], default: 'pending' },
    createdAt: { type: Date, default: Date.now },
    ipAddress: String,
    userAgent: String
});

const eventSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    date: { type: Date, required: true },
    location: {
        address: String,
        city: String,
        country: String,
        coordinates: {
            latitude: Number,
            longitude: Number
        }
    },
    organizer: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    maxParticipants: { type: Number, default: 100 },
    tags: [String],
    image: String,
    status: { type: String, enum: ['draft', 'published', 'cancelled'], default: 'draft' },
    createdAt: { type: Date, default: Date.now }
});

const blogSchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true },
    excerpt: String,
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    tags: [String],
    image: String,
    status: { type: String, enum: ['draft', 'published'], default: 'draft' },
    views: { type: Number, default: 0 },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    comments: [{
        user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        content: String,
        createdAt: { type: Date, default: Date.now }
    }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);
const Event = mongoose.model('Event', eventSchema);
const Blog = mongoose.model('Blog', blogSchema);

// Email configuration
const transporter = nodemailer.createTransporter({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Middleware for authentication
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'peace-secret-key', (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Admin middleware
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Admin access required' });
    }
    next();
};

// API Routes

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'Peace Lover World API is running', timestamp: new Date() });
});

// Contact form submission
app.post('/api/contact', async (req, res) => {
    try {
        const { name, email, message, subject } = req.body;
        
        if (!name || !email || !message) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        const newMessage = new Message({
            name,
            email,
            subject: subject || 'Peace Message',
            message,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent')
        });

        await newMessage.save();

        // Send email notification
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: process.env.ADMIN_EMAIL,
            subject: `New Peace Message from ${name}`,
            html: `
                <h2>New Message from Peace Lover World</h2>
                <p><strong>Name:</strong> ${name}</p>
                <p><strong>Email:</strong> ${email}</p>
                <p><strong>Subject:</strong> ${subject || 'Peace Message'}</p>
                <p><strong>Message:</strong></p>
                <p>${message}</p>
                <p><strong>Received:</strong> ${new Date().toLocaleString()}</p>
            `
        };

        await transporter.sendMail(mailOptions);

        res.status(201).json({ 
            message: 'Your message has been sent successfully!',
            messageId: newMessage._id 
        });
    } catch (error) {
        console.error('Contact form error:', error);
        res.status(500).json({ message: 'Error sending message' });
    }
});

// User registration
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET || 'peace-secret-key');

        const newUser = new User({
            name,
            email,
            password: hashedPassword,
            verificationToken
        });

        await newUser.save();

        // Send verification email
        const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`;
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Welcome to Peace Lover World - Verify Your Email',
            html: `
                <h2>Welcome to Peace Lover World!</h2>
                <p>Thank you for joining our community of peace lovers.</p>
                <p>Please verify your email address by clicking the link below:</p>
                <a href="${verificationUrl}">Verify Email</a>
                <p>If you didn't create this account, please ignore this email.</p>
            `
        };

        await transporter.sendMail(mailOptions);

        res.status(201).json({ 
            message: 'User registered successfully! Please check your email to verify your account.',
            userId: newUser._id 
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Error creating user' });
    }
});

// User login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        if (!user.isVerified) {
            return res.status(401).json({ message: 'Please verify your email before logging in' });
        }

        const token = jwt.sign(
            { userId: user._id, email: user.email, role: user.role },
            process.env.JWT_SECRET || 'peace-secret-key',
            { expiresIn: '24h' }
        );

        user.lastLogin = new Date();
        await user.save();

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                profile: user.profile
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Error during login' });
    }
});

// Get all events
app.get('/api/events', async (req, res) => {
    try {
        const { page = 1, limit = 10, city, country, upcoming } = req.query;
        const query = { status: 'published' };

        if (city) query['location.city'] = new RegExp(city, 'i');
        if (country) query['location.country'] = new RegExp(country, 'i');
        if (upcoming === 'true') query.date = { $gte: new Date() };

        const events = await Event.find(query)
            .populate('organizer', 'name profile.avatar')
            .sort({ date: 1 })
            .limit(limit * 1)
            .skip((page - 1) * limit);

        const total = await Event.countDocuments(query);

        res.json({
            events,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            total
        });
    } catch (error) {
        console.error('Events fetch error:', error);
        res.status(500).json({ message: 'Error fetching events' });
    }
});

// Create event (authenticated users only)
app.post('/api/events', authenticateToken, async (req, res) => {
    try {
        const eventData = {
            ...req.body,
            organizer: req.user.userId
        };

        const newEvent = new Event(eventData);
        await newEvent.save();

        res.status(201).json({ message: 'Event created successfully', event: newEvent });
    } catch (error) {
        console.error('Event creation error:', error);
        res.status(500).json({ message: 'Error creating event' });
    }
});

// Get blog posts
app.get('/api/blog', async (req, res) => {
    try {
        const { page = 1, limit = 10, tag } = req.query;
        const query = { status: 'published' };

        if (tag) query.tags = tag;

        const posts = await Blog.find(query)
            .populate('author', 'name profile.avatar')
            .sort({ createdAt: -1 })
            .limit(limit * 1)
            .skip((page - 1) * limit);

        const total = await Blog.countDocuments(query);

        res.json({
            posts,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            total
        });
    } catch (error) {
        console.error('Blog fetch error:', error);
        res.status(500).json({ message: 'Error fetching blog posts' });
    }
});

// Get single blog post
app.get('/api/blog/:id', async (req, res) => {
    try {
        const post = await Blog.findById(req.params.id)
            .populate('author', 'name profile.avatar')
            .populate('comments.user', 'name profile.avatar');

        if (!post) {
            return res.status(404).json({ message: 'Post not found' });
        }

        // Increment view count
        post.views += 1;
        await post.save();

        res.json(post);
    } catch (error) {
        console.error('Blog post fetch error:', error);
        res.status(500).json({ message: 'Error fetching blog post' });
    }
});

// Admin routes
app.get('/api/admin/messages', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 20, status } = req.query;
        const query = status ? { status } : {};

        const messages = await Message.find(query)
            .sort({ createdAt: -1 })
            .limit(limit * 1)
            .skip((page - 1) * limit);

        const total = await Message.countDocuments(query);

        res.json({
            messages,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            total
        });
    } catch (error) {
        console.error('Messages fetch error:', error);
        res.status(500).json({ message: 'Error fetching messages' });
    }
});

app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const totalMessages = await Message.countDocuments();
        const totalEvents = await Event.countDocuments();
        const totalBlogs = await Blog.countDocuments();

        const recentMessages = await Message.find()
            .sort({ createdAt: -1 })
            .limit(5);

        const upcomingEvents = await Event.find({ date: { $gte: new Date() } })
            .sort({ date: 1 })
            .limit(5);

        res.json({
            stats: {
                totalUsers,
                totalMessages,
                totalEvents,
                totalBlogs
            },
            recentMessages,
            upcomingEvents
        });
    } catch (error) {
        console.error('Stats fetch error:', error);
        res.status(500).json({ message: 'Error fetching stats' });
    }
});

// Newsletter subscription
app.post('/api/newsletter', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ message: 'Email is required' });
        }

        // Here you would typically save to a newsletter collection
        // For now, we'll just send a welcome email

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Welcome to Peace Lover World Newsletter',
            html: `
                <h2>Welcome to Our Peace Community!</h2>
                <p>Thank you for subscribing to our newsletter.</p>
                <p>You'll receive updates about peace initiatives, events, and inspiring stories from around the world.</p>
                <p>Together, we can make the world a more peaceful place.</p>
            `
        };

        await transporter.sendMail(mailOptions);

        res.json({ message: 'Successfully subscribed to newsletter!' });
    } catch (error) {
        console.error('Newsletter subscription error:', error);
        res.status(500).json({ message: 'Error subscribing to newsletter' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!' });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ message: 'Endpoint not found' });
});

// Start server
app.listen(PORT, () => {
    console.log(`Peace Lover World API server running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;