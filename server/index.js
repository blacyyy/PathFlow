import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import { GoogleGenerativeAI } from "@google/generative-ai";
import LearningPath from "./models/LearningPath.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import cookieParser from "cookie-parser";
import User from "./models/User.js";

// Load environment variables
dotenv.config();

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.CLIENT_URL || "http://localhost:3000",
  credentials: true
}));
app.use(cookieParser());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // limit each IP to 50 requests per windowMs
  message: "Too many requests from this IP, please try again later."
});
app.use(limiter);

// API-specific rate limiting for AI generation
const aiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5, // 5 AI requests per minute
  message: "AI generation limit exceeded. Please wait a moment."
});

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// MongoDB connection with graceful handling
let isMongoConnected = false;

const connectMongoDB = async () => {
  if (!process.env.MONGO_URI) {
    console.log("⚠️ MONGO_URI not provided - running without database");
    return;
  }

  try {
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000, // Timeout after 5s instead of 30s
      socketTimeoutMS: 45000,
    });
    isMongoConnected = true;
    console.log("✅ MongoDB connected successfully");
  } catch (err) {
    console.error("⚠️ MongoDB connection failed:", err.message);
    console.log("🔄 Server will continue running without database functionality");
    isMongoConnected = false;
  }
};

// Connect to MongoDB (non-blocking)
connectMongoDB();

// Handle MongoDB connection events
mongoose.connection.on('connected', () => {
  isMongoConnected = true;
  console.log('✅ MongoDB connected');
});

mongoose.connection.on('disconnected', () => {
  isMongoConnected = false;
  console.log('⚠️ MongoDB disconnected - database features unavailable');
});

mongoose.connection.on('reconnected', () => {
  isMongoConnected = true;
  console.log('✅ MongoDB reconnected');
});

mongoose.connection.on('error', (err) => {
  isMongoConnected = false;
  console.error('⚠️ MongoDB error:', err.message);
});

// Setup Gemini AI client with error handling
let model;
try {
  if (!process.env.GEMINI_API_KEY) {
    throw new Error("GEMINI_API_KEY is not configured");
  }
  const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
  model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
  console.log("✅ Gemini AI initialized");
} catch (error) {
  console.error("❌ Gemini AI initialization failed:", error.message);
}

// Validation middleware
const validateLearningPathInput = (req, res, next) => {
  const { skills, goal } = req.body;
  
  if (!skills || typeof skills !== 'string' || skills.trim().length === 0) {
    return res.status(400).json({ 
      error: "Skills are required and must be a non-empty string" 
    });
  }
  
  if (!goal || typeof goal !== 'string' || goal.trim().length === 0) {
    return res.status(400).json({ 
      error: "Goal is required and must be a non-empty string" 
    });
  }
  
  if (skills.length > 200 || goal.length > 100) {
    return res.status(400).json({ 
      error: "Skills or goal text is too long" 
    });
  }
  
  next();
};

// Utility function to clean and parse steps
const parseStepsFromResponse = (text) => {
  const steps = text
    .split("\n")
    .map(line => line.trim())
    .filter(line => line && /^\d+\./.test(line))
    .map(step => step.replace(/^\d+\.\s*/, ""))
    .filter(step => step.length > 0);
  
  return steps.length > 0 ? steps : null;
};

// Fallback learning path generator
const generateFallbackPath = (skills, goal) => {
  return [
    `Review and strengthen your current ${skills} skills`,
    `Research the specific requirements and technologies for ${goal}`,
    `Learn the fundamental concepts and tools needed for ${goal}`,
    `Build small practice projects to apply your new knowledge`,
    `Create a comprehensive portfolio showcasing your ${goal} skills`,
    `Network with professionals and apply for ${goal} positions`
  ];
};

// Routes
// Auth helpers
const signToken = (user) => {
  const jwtSecret = process.env.JWT_SECRET || "dev-secret-change";
  return jwt.sign({ id: user._id, email: user.email }, jwtSecret, { expiresIn: "7d" });
};

const authRequired = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : (req.cookies?.token || null);
    if (!token) return res.status(401).json({ success: false, error: "Unauthorized" });
    const jwtSecret = process.env.JWT_SECRET || "dev-secret-change";
    const payload = jwt.verify(token, jwtSecret);
    req.user = payload;
    return next();
  } catch (err) {
    return res.status(401).json({ success: false, error: "Invalid or expired token" });
  }
};

// Auth routes
app.post("/auth/register", async (req, res) => {
  try {
    if (!isMongoConnected) return res.status(503).json({ success: false, error: "Database unavailable" });
    const { name, email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, error: "Email and password required" });
    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) return res.status(409).json({ success: false, error: "Email already in use" });
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ name: name?.trim(), email: email.toLowerCase(), passwordHash });
    const token = signToken(user);
    return res.status(201).json({ success: true, token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (err) {
    console.error("Auth register error:", err.message);
    return res.status(500).json({ success: false, error: "Registration failed" });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    if (!isMongoConnected) return res.status(503).json({ success: false, error: "Database unavailable" });
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, error: "Email and password required" });
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(401).json({ success: false, error: "Invalid credentials" });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ success: false, error: "Invalid credentials" });
    const token = signToken(user);
    return res.json({ success: true, token, user: { id: user._id, name: user.name, email: user.email } });
  } catch (err) {
    console.error("Auth login error:", err.message);
    return res.status(500).json({ success: false, error: "Login failed" });
  }
});

app.get("/auth/me", authRequired, async (req, res) => {
  try {
    if (!isMongoConnected) return res.status(503).json({ success: false, error: "Database unavailable" });
    const user = await User.findById(req.user.id).lean();
    if (!user) return res.status(404).json({ success: false, error: "User not found" });
    return res.json({ success: true, user: { id: user._id, name: user.name, email: user.email } });
  } catch (err) {
    return res.status(500).json({ success: false, error: "Failed to fetch user" });
  }
});
app.get("/", (req, res) => {
  res.json({
    message: "🚀 Learning Path Generator API",
    version: "1.0.0",
    status: "running",
    endpoints: ["/generate-path", "/generate-roadmap-steps"]
  });
});

// Health check endpoint
app.get("/health", async (req, res) => {
  const health = {
    uptime: process.uptime(),
    message: "OK",
    timestamp: Date.now(),
    database: isMongoConnected ? "connected" : "disconnected",
    ai: !!model ? "available" : "unavailable"
  };
  
  try {
    res.status(200).json(health);
  } catch (error) {
    health.message = "ERROR";
    res.status(503).json(health);
  }
});

// Main AI-powered learning path generation (detailed text steps)
app.post("/generate-path", authRequired, aiLimiter, validateLearningPathInput, async (req, res) => {
  const { skills, goal } = req.body;
  const startTime = Date.now();
  
  try {
    let generatedSteps = null;
    
    // Try to generate with AI first
    if (model) {
      const prompt = `
You are a professional career coach and learning specialist.

Create a clear, actionable, step-by-step learning path for someone who currently knows: "${skills}" and wants to become a "${goal}".

Requirements:
- Provide exactly 6 steps
- Each step should be specific and actionable
- Start each step with an action verb
- Make it beginner-friendly but comprehensive
- Focus on practical skills and real-world application
- Include both learning and doing components

Format: Return only the numbered steps, nothing else.
`;

      try {
        const result = await model.generateContent(prompt);
        const text = result.response.text();
        generatedSteps = parseStepsFromResponse(text);
        
        if (!generatedSteps) {
          console.warn("⚠️ AI generated invalid format, using fallback");
        }
      } catch (aiError) {
        console.error("⚠️ AI generation failed:", aiError.message);
      }
    }
    
    // Use fallback if AI failed or returned invalid format
    const finalSteps = generatedSteps || generateFallbackPath(skills, goal);
    
    // Save to database (non-blocking, only if MongoDB is connected)
    const savePromise = (async () => {
      if (!isMongoConnected) {
        console.log("⚠️ Skipping database save - MongoDB not connected");
        return;
      }

      try {
        const skillsArray = skills
          .split(/[,;]/)
          .map(s => s.trim())
          .filter(Boolean)
          .slice(0, 10); // Limit to 10 skills
        
        await LearningPath.create({
          skills: skillsArray.length ? skillsArray : [skills],
          goal: goal.trim(),
          path: finalSteps,
          generatedBy: 'ai',
          createdAt: new Date(),
          metadata: {
            responseTime: Date.now() - startTime,
            aiUsed: !!generatedSteps
          }
        });
        
        console.log("✅ Learning path saved to database");
      } catch (dbError) {
        console.error("⚠️ Database save failed (non-critical):", dbError.message);
      }
    })();
    
    // Don't wait for database save
    savePromise.catch(() => {});
    
    // Return response
    res.json({
      success: true,
      steps: finalSteps.map((step, index) => `${index + 1}. ${step}`),
      metadata: {
        generatedBy: generatedSteps ? 'ai' : 'fallback',
        responseTime: Date.now() - startTime,
        timestamp: Date.now()
      }
    });
    
  } catch (error) {
    console.error("❌ Error in /generate-path:", error);
    
    // Return fallback response
    const fallbackSteps = generateFallbackPath(skills, goal);
    res.status(200).json({
      success: true,
      steps: fallbackSteps.map((step, index) => `${index + 1}. ${step}`),
      metadata: {
        generatedBy: 'fallback',
        responseTime: Date.now() - startTime,
        error: 'Service temporarily unavailable'
      }
    });
  }
});

// NEW: Simplified roadmap step generator (for canvas)
app.post("/generate-roadmap-steps", authRequired, aiLimiter, validateLearningPathInput, async (req, res) => {
  const { skills, goal } = req.body;

  try {
    const prompt = `
Generate a simplified learning roadmap.
Input skills: "${skills}"
Goal: "${goal}"

Rules:
- Exactly 6 steps
- Each step max 6 words
- Start with an action verb
- Return only the plain steps (no numbering, no explanation)
`;

    const result = await model.generateContent(prompt);
    const text = result.response.text();

    const steps = text
      .split("\n")
      .map(s => s.replace(/^\d+\.\s*/, "").trim())
      .filter(Boolean);

    res.json({
      success: true,
      steps
    });
  } catch (err) {
    console.error("❌ Roadmap generation failed:", err.message);
    res.status(500).json({ success: false, error: "Failed to generate roadmap" });
  }
});

// Get saved learning paths (for dashboard)
app.get("/paths", authRequired, async (req, res) => {
  if (!isMongoConnected) {
    return res.status(503).json({
      success: false,
      error: "Database service unavailable"
    });
  }

  try {
    const { limit = 10, skip = 0 } = req.query;
    
    const paths = await LearningPath
      .find({})
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(parseInt(skip))
      .lean();
    
    const total = await LearningPath.countDocuments();
    
    res.json({
      success: true,
      data: paths,
      pagination: {
        total,
        limit: parseInt(limit),
        skip: parseInt(skip),
        hasMore: total > parseInt(skip) + paths.length
      }
    });
  } catch (error) {
    console.error("❌ Error fetching paths:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch learning paths"
    });
  }
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("🚨 Unhandled error:", err);
  
  res.status(err.status || 500).json({
    success: false,
    error: process.env.NODE_ENV === 'production' 
      ? 'Internal server error' 
      : err.message
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: "Endpoint not found"
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('👋 SIGTERM received, shutting down gracefully');
  if (isMongoConnected) {
    mongoose.connection.close(() => {
      console.log('📦 Database connection closed');
      process.exit(0);
    });
  } else {
    process.exit(0);
  }
});

process.on('SIGINT', () => {
  console.log('👋 SIGINT received, shutting down gracefully');
  if (isMongoConnected) {
    mongoose.connection.close(() => {
      console.log('📦 Database connection closed');
      process.exit(0);
    });
  } else {
    process.exit(0);
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  
  if (!process.env.MONGO_URI) {
    console.log('⚠️ Note: Running without MongoDB (set MONGO_URI to enable database features)');
  }
  
  if (!process.env.GEMINI_API_KEY) {
    console.log('⚠️ Note: Running without Gemini AI (set GEMINI_API_KEY to enable AI features)');
  }
});

export default app;
