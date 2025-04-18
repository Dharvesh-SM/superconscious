import express, { Request, Response } from "express";
import jwt from "jsonwebtoken";
import z from "zod";
import bcrypt from "bcrypt";
import mongoose from "mongoose";
import { UserModel, ContentModel, LinkModel } from "./db";
import dotenv from "dotenv";
import { auth } from "./middleware";
import { random } from "./utils";
import cors from "cors";
import puppeteer from "puppeteer";
import { GoogleGenerativeAI } from "@google/generative-ai";
import { Index, Pinecone } from "@pinecone-database/pinecone";
import passport from 'passport';
import session from 'express-session';
import { setupGoogleAuth, generateTokenForGoogleUser } from './googleAuth';

dotenv.config();

// Type definitions
interface User {
  _id: mongoose.Types.ObjectId;
  username: string;
  password: string;
}

interface Content {
  _id: mongoose.Types.ObjectId;
  title: string;
  link?: string;
  type: string;
  content: string;
  tag: string[];
  userId: mongoose.Types.ObjectId;
  imageUrl?: string;
}

interface Link {
  _id: mongoose.Types.ObjectId;
  userId: mongoose.Types.ObjectId;
  hash: string;
}

interface AuthRequest extends Request {
  userId?: string;
}

interface SearchQuery {
  query: string;
}

interface ScrapedData {
  title: string;
  content: string;
  imageUrl?: string | null; // Allow imageUrl to be null or undefined
}

// Initialize Express
const app = express();

app.use(
  cors({
    origin: [
      "https://consciousapp.vercel.app",
      "https://cronify-web-rho.vercel.app",
      "http://localhost:5173",
    ],
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);

// Set up session middleware (required for passport)
app.use(session({
  secret: process.env.SESSION_SECRET || process.env.JWT_SECRET as string,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));

// Set up passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Set up Google authentication
setupGoogleAuth();

const port = process.env.PORT || 3000;

app.use(express.json());

// Initialize Pinecone client
const initPinecone = async () => {
  const pinecone = new Pinecone({
    apiKey: process.env.PINECONE_API_KEY as string,
    // Note: environment is no longer needed in the newer SDK
  });

  // Get the index directly from the pinecone instance
  return pinecone.index(process.env.PINECONE_INDEX as string);
};

let pineconeIndex: Index;

// Initialize Gemini API
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY as string);
const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

// Function to get embeddings from Gemini
// Update your getEmbedding function
async function getEmbedding(text: string): Promise<number[]> {
  const embeddingModel = genAI.getGenerativeModel({ model: "embedding-001" });
  const result = await embeddingModel.embedContent(text);

  // Try to access the values property if it exists
  if (result.embedding && typeof result.embedding === "object") {
    if (
      "values" in result.embedding &&
      Array.isArray(result.embedding.values)
    ) {
      return result.embedding.values;
    } else if (Array.isArray(result.embedding)) {
      return result.embedding;
    }
  }

  console.error("Unexpected embedding format:", result.embedding);
  throw new Error("Failed to get valid embedding");
}

// Add this helper function near the top with other utility functions
function isValidImageUrl(url: string | null): boolean {
  if (!url) return false;
  // Skip blob URLs as they are temporary and won't work when stored
  if (url.startsWith('blob:')) return false;
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

// Function to scrape URL content
async function scrapeUrl(url: string): Promise<ScrapedData> {
  let browser;
  try {
    console.log(`Node environment: ${process.env.NODE_ENV}`);
    console.log(
      `Puppeteer package version: ${require("puppeteer/package.json").version}`
    );

    // For local development, we'll prioritize finding an installed Chrome
    let executablePath;
    if (process.env.NODE_ENV === 'development' && process.platform === 'win32') {
      // Common Chrome paths on Windows
      const possiblePaths = [
        'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
        'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
        process.env.LOCALAPPDATA + '\\Google\\Chrome\\Application\\chrome.exe'
      ];
      
      // Use the first path that exists
      for (const path of possiblePaths) {
        try {
          if (require('fs').existsSync(path)) {
            executablePath = path;
            console.log(`Using local Chrome at: ${executablePath}`);
            break;
          }
        } catch (e) {
          // Continue to next path
        }
      }
    }
    
    // Fall back to environment variable or Puppeteer's bundled Chrome
    if (!executablePath) {
      if (process.env.PUPPETEER_EXECUTABLE_PATH) {
        executablePath = process.env.PUPPETEER_EXECUTABLE_PATH;
        console.log(`Using Chrome at: ${executablePath}`);
      } else {
        executablePath = puppeteer.executablePath();
        console.log(`Using bundled Chrome at: ${executablePath}`);
      }
    }

    // Launch browser with appropriate settings for local development
    browser = await puppeteer.launch({
      executablePath,
      timeout: 120000, // 2 minutes
      headless: process.env.NODE_ENV === 'production', // Use non-headless for local debugging
      args: [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        "--disable-features=IsolateOrigins,site-per-process",
        "--disable-web-security",
        // Only use these args in production
        ...(process.env.NODE_ENV === 'production' ? ["--single-process", "--no-zygote"] : []),
      ],
    });

    const page = await browser.newPage();
    
    // Set user agent to mimic a real browser
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36');
    
    // Set longer timeouts for page operations
    await page.setDefaultNavigationTimeout(120000);
    await page.setDefaultTimeout(120000);

    // Improved error handling for navigation
    try {
      // Use a more lenient waitUntil strategy
      await page.goto(url, { 
        waitUntil: "domcontentloaded", // Only wait for DOM to load, not for all resources
        timeout: 60000 // 1 minute timeout
      });
      
      // Add small delay to ensure some content loads
      await new Promise((resolve) => setTimeout(resolve, 1000));
    } catch (navError) {
      const errorMessage = navError instanceof Error ? navError.message : 'Unknown navigation error';
      console.error(`Navigation error: ${errorMessage}`);
      return {
        title: "Navigation Failed",
        content: `Could not access the page content. This might be because the website is blocking automated access or the page no longer exists.`,
        imageUrl: null
      };
    }

    // Check if page is still valid
    if (page.isClosed()) {
      return {
        title: "Page Closed Unexpectedly",
        content: "The browser page was closed during navigation. This might be due to website security measures.",
        imageUrl: null
      };
    }

    // Extract data with try/catch blocks for each operation
    let title = "No title available";
    try {
      title = await page.title();
    } catch (e) {
      console.error("Error getting title:", e);
    }

    let metaImage = null;
    try {
      metaImage = await page.evaluate(() => {
        const metaSelectors = [
          'meta[property="og:image"]',
          'meta[name="twitter:image"]',
          'meta[property="og:image:secure_url"]',
          'meta[itemprop="image"]',
          'link[rel="image_src"]',
          'link[rel="icon"]',
        ];

        for (const selector of metaSelectors) {
          const element = document.querySelector(selector);
          const content = element?.getAttribute('content') || element?.getAttribute('href');
          if (content) return content;
        }
        return null;
      });
    } catch (e) {
      console.error("Error extracting meta image:", e);
    }

    // Make URL absolute and validate
    const imageUrl = metaImage ? new URL(metaImage, url).toString() : null;
    const finalImageUrl = isValidImageUrl(imageUrl) ? imageUrl : null;

    // Extract content with error handling
    let content = "Failed to extract content from page";
    try {
      content = await page.evaluate(() => {
        const paragraphs = Array.from(document.querySelectorAll("p")).map(
          (p) => p.textContent
        );
        const headings = Array.from(document.querySelectorAll("h1, h2, h3")).map(
          (h) => h.textContent
        );
        return [...headings, ...paragraphs].filter(Boolean).join(" ").trim();
      });
    } catch (e) {
      console.error("Error extracting content:", e);
    }

    return { title, content, imageUrl: finalImageUrl };
  } catch (error) {
    console.error("Error scraping URL:", error);
    if (error instanceof Error) {
      if (error.message.includes('timeout')) {
        return {
          title: "Scraping Failed - Timeout",
          content: "The page took too long to load. This might be due to slow connection or complex page content.",
          imageUrl: null
        };
      }
      if (error.message.includes('detached')) {
        return {
          title: "Scraping Failed - Page Detached",
          content: "The website may be using anti-scraping measures or redirects that prevent automated access. Try visiting the URL directly in your browser.",
          imageUrl: null
        };
      }
      console.error(error.stack);
    } else {
      console.error("An unknown error occurred:", error);
    }
    return {
      title: "Failed to scrape",
      content: `Error: ${error instanceof Error ? error.message : "Unknown error"}`,
      imageUrl: null
    };
  } finally {
    if (browser) {
      await browser.close().catch(console.error);
    }
  }
}

const dbconnect = async (): Promise<void> => {
  try {
    await mongoose.connect(process.env.MONGO_URL as string);
    console.log("Connected to MongoDB");

    // Initialize Pinecone
    pineconeIndex = await initPinecone();
    console.log("Connected to Pinecone");

    app.listen(port, () => {
      console.log(`Server is running on port ${port}`);
      console.log(`Google Auth URL: http://localhost:${port}/api/v1/auth/google`);
    });
  } catch (error) {
    console.log("Error connecting to db");
    console.log(error);
    process.exit(1);
  }
};
// Google Auth Routes 
// Update the Google auth route to include prompt and access_type parameters
app.get('/api/v1/auth/google', 
  (req, res, next) => {
    const authOptions = {
      scope: ['profile', 'email'],
      prompt: 'select_account',  // Force account selection
      accessType: 'online'
    };
    
    // Clear any existing session to ensure fresh authentication
    if (req.session) {
      req.session.destroy(() => {
        passport.authenticate('google', authOptions)(req, res, next);
      });
    } else {
      passport.authenticate('google', authOptions)(req, res, next);
    }
  }
);
// Google auth callback route
  app.get('/api/v1/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/api/v1/auth/failure' }),
  (req: any, res: Response): void => {
    if (!req.user) {
      res.status(401).json({ message: 'Authentication failed' });
      return;
    }
    
    // Check if this was a new user created during this authentication
    const isNewUser = req.user.isNewAccount || false;
    
    const token = generateTokenForGoogleUser(req.user._id);
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
    res.redirect(`${frontendUrl}/auth-callback?token=${token}&username=${encodeURIComponent(req.user.username)}&isNewUser=${isNewUser}`);
  }
);

app.get('/api/v1/auth/failure', (req: Request, res: Response) => {
  res.status(401).json({ message: 'Google authentication failed' });
});

// Add a test endpoint to verify authentication
app.get('/api/v1/auth/test', auth, (req: AuthRequest, res: Response) => {
  res.json({
    message: 'Authentication is working!',
    userId: req.userId
  });
});

// Log registered google routes
console.log('Routes registered:');
app._router.stack.forEach((r: any) => {
  if (r.route && r.route.path) {
    console.log(`${Object.keys(r.route.methods)} ${r.route.path}`);
  }
});


dbconnect();

app.get("/", (_req: Request, res: Response) => {
  res.send("Second Brain API is running!");
});

// -------------------signup-------------------

app.post("/api/v1/signup", async (req: Request, res: Response) => {
  const inputzod = z.object({
    username: z
      .string()
      .min(3, { message: "Username must be at least 3 characters long " })
      .max(12, { message: "Username must be at most 12 characters long " }),

    password: z
      .string()
      .min(6, { message: "Password must be at least 6 characters long " })
      .max(12, { message: "Password must be at most 12 characters long " })
      .regex(/[!@#$%^&*(),.?":{}|<>]/, {
        message: "Password must contain at least one special character",
      }),
  });
  
  const validInput = inputzod.safeParse(req.body);
  if (!validInput.success) {
    const errorMessage = validInput.error.errors.map((e) => e.message);
    res.status(411).json({
      message: errorMessage || "Invalid format",
      error: errorMessage,
    });
    return;
  }

  const { username, password } = req.body;
  const hashpassword = await bcrypt.hash(password, 10);
  try {
    const user = await UserModel.findOne({ username });
    if (!user) {
      await UserModel.create({ username, password: hashpassword });
    } else {
      res.status(500).json({ message: "User name is taken" });
      return;
    }
    res.status(200).json({ message: "User created successfully" });
  } catch (err) {
    res.status(500).json({ message: "Internal server error" });
  }
});

// -------------------signin-------------------

app.post("/api/v1/signin", async (req: Request, res: Response) => {
  const { username, password } = req.body;

  const user = await UserModel.findOne({ username });
  if (!user) {
    res.status(404).json({ message: "user not found" });
    return;
  }
  if (user === null) {
    res.status(401).json({ message: "Invalid credentials" });
    return;
  }
  if (user.password) {
    try {
      const hashpassword = await bcrypt.compare(password, user.password);
      if (hashpassword) {
        if (user._id) {
          const token = jwt.sign(
            { id: user._id },
            process.env.JWT_SECRET as string,
            { expiresIn: "7days" }
          );
          res.status(200).json({ message: "User logged in successfully", token, username });
        }
      } else {
        res.status(401).json({ message: "Invalid credentials" });
      }
    } catch (error) {
      res.status(500).json({ message: "Internal server error" });
    }
  } else {
    res.status(401).json({ message: "Invalid credentials" });
  }
});

// -------------------content add with vector embedding------

app.post("/api/v1/content", auth, async (req: AuthRequest, res: Response) => {
  const { link, title, type, content } = req.body;

  try {
    let contentToSave = content || "";
    let titleToSave = title || "";
    let imageUrl: string | null = null;

    if (type === "Url" && link) {
      const scrapedData = await scrapeUrl(link);
      
      if (scrapedData.content) contentToSave = scrapedData.content;
      if (!titleToSave && scrapedData.title) titleToSave = scrapedData.title;
      // Validate image URL before saving
      if (scrapedData.imageUrl && isValidImageUrl(scrapedData.imageUrl)) {
        imageUrl = scrapedData.imageUrl;
      }
    }

    // Generate timestamp in a human-readable format
    const timestamp = new Date().toLocaleString();

    // Prepare text for embedding (Ensure it's a valid string)
    const textForEmbedding = `Title: ${titleToSave}\nDate: ${timestamp}\nContent: ${contentToSave}`;

    // Save to MongoDB
    const newContent = await ContentModel.create({
      title: titleToSave,
      link,
      type,
      content: contentToSave,
      imageUrl, // ✅ Save scraped image URL
      tag: [],
      userId: req.userId,
      createdAt: new Date(),
    });

    // Generate vector embedding
    const embedding = await getEmbedding(textForEmbedding);

    // Upsert into Pinecone
    await pineconeIndex.upsert([
      {
        id: newContent._id.toString(),
        values: embedding,
        metadata: {
          userId: req.userId?.toString() || "",
          title: titleToSave,
          contentType: type,
          timestamp: timestamp,
          snippet: contentToSave.substring(0, 100),
          imageUrl: imageUrl || "", // ✅ Store image URL in metadata
        },
      },
    ]);

    res.status(200).json({ message: "Content added successfully", contentId: newContent._id ,imageUrl: imageUrl || null});
  } catch (err) {
    console.error("Error adding content:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// -------------------content get-------------------

app.get("/api/v1/content", auth, async (req: AuthRequest, res: Response) => {
  const userId = req.userId;
  try {
    const content = await ContentModel.find({ userId: userId }).populate(
      "userId",
      "username"
    );
    if (content.length == 0) {
      res.json({
        content: [
          {
            _id: "default-1",
            type: "Note",
            title: "Welcome to Conscious!",
            content:
              "This is your default content. Start exploring now! click on Add Memory to add more content",
              imageUrl: null,
          },
        ],
      });
      return;
    }
    res.status(200).json({
      content: content.map((item) => ({
        _id: item._id,
        title: item.title,
        type: item.type,
        content: item.content,
        link: item.link || null,
        imageUrl: item.imageUrl || null, // Include imageUrl in the response
        userId: item.userId,
        createdAt: item.createdAt,
      })),
    });
    return;
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error" });
    return;
  }
});

// -------------------content delete-------------------

app.delete(
  "/api/v1/content/:contentId",
  auth,
  async (req: AuthRequest, res: Response) => {
    const { contentId } = req.params;

    if (!contentId || !mongoose.Types.ObjectId.isValid(contentId)) {
      res.status(400).json({ error: "Invalid or missing content ID" });
      return;
    }

    try {
      // Delete from MongoDB
      await ContentModel.deleteOne({ _id: contentId, userId: req.userId });

      // Delete from Pinecone
      await pineconeIndex.deleteOne(contentId);

      // Or if you want to delete multiple IDs, use:
      // await pineconeIndex.deleteMany([contentId]);

      res.json({ message: "Content deleted successfully" });
    } catch (error) {
      console.error("Error deleting content:", error);
      res.status(500).json({ message: "Error deleting content" });
    }
  }
);
// -------------------search endpoint-------------------

app.post(
  "/api/v1/search",
  auth,
  async (req: AuthRequest, res: Response): Promise<void> => {
    const { query } = req.body as SearchQuery;
    const userId = req.userId;

    if (!query || query.trim() === "") {
      res.status(400).json({ message: "Search query is required" });
      return;
    }

    try {
      // Get embedding for the query
      const queryEmbedding = await getEmbedding(query);

      // Search in vector database for similar content
      const searchResponse = await pineconeIndex.query({
        vector: queryEmbedding,
        topK: 5,
        includeMetadata: true,
        filter: {
          userId: userId?.toString() || "",
        },
      });

      // Extract relevant content from database based on vector search results
      const contentIds = searchResponse.matches.map((match: any) => match.id);
      const relevantContent = await ContentModel.find({
        _id: { $in: contentIds },
        userId: userId,
      });

      // Map content to include similarity score
      const contentWithScores = relevantContent
        .map((content: any) => {
          const match = searchResponse.matches.find(
            (m: any) => m.id === content._id.toString()
          );
          return {
            ...content.toObject(),
            similarityScore: match ? match.score : 0,
          };
        })
        .sort((a: any, b: any) => b.similarityScore - a.similarityScore)
        .slice(0, 2);

      // If no relevant content found
      if (contentWithScores.length === 0) {
        res.json({
          message:
            "No relevant content found in your second brain for this query.",
          results: [],
        });
        return;
      }

      // Rest of your code remains the same...
      let context =
        "Below is the relevant information from the user's second brain:\n\n";
      contentWithScores.forEach((item: any, index: number) => {
        context += `[Content ${index + 1}]\nTitle: ${item.title}\nType: ${
          item.type
        }\n`;
        if (item.link) context += `Link: ${item.link}\n`;
        context += `Content: ${item.content}\n\n`;
      });

      const prompt = `${context}\n\nUser query: "${query}"\n\nBased on the information above from the user's second brain, please provide a helpful and concise response to their query. If the information doesn't contain a direct answer, try to extract relevant insights that might be helpful. if any questions asked also try to answer it.`;
      const result = await model.generateContent({
        contents: [{ role: "user", parts: [{ text: prompt }] }],
      });

      const answer =
        result?.response?.candidates?.[0]?.content?.parts?.[0]?.text ||
        "No response generated.";

      res.json({
        message: "Search results found",
        relevantContent: contentWithScores,
        answer: answer,
      });
    } catch (error) {
      console.error("Search error:", error);
      res.status(500).json({ message: "Error processing search request" });
    }
  }
);
// -------------------brain share-------------------

app.post(
  "/api/v1/brain/share",
  auth,
  async (req: AuthRequest, res: Response) => {
    const share = req.body.share;
    if (share) {
      const content = await LinkModel.findOne({ userId: req.userId });
      if (content) {
        res.json({ hash: content.hash });
        return;
      }
      const hash = random(10);
      await LinkModel.create({
        userId: req.userId,
        hash: hash,
      });

      res.json({
        hash,
      });
    } else {
      await LinkModel.deleteOne({
        userId: req.userId,
      });

      res.json({
        message: "Removed link",
      });
    }
  }
);

app.get("/api/v1/brain/:shareLink", async (req: Request, res: Response) => {
  const hash = req.params.shareLink;

  const link = await LinkModel.findOne({
    hash,
  });

  if (!link) {
    res.status(411).json({
      message: "Sorry incorrect input",
    });
    return;
  }

  const content = await ContentModel.find({
    userId: link.userId,
  });

  const user = await UserModel.findOne({
    _id: link.userId,
  });

  if (!user) {
    res.status(411).json({
      message: "user not found, error should ideally not happen",
    });
    return;
  }

  res.json({
    username: user.username,
    content: content,
  });
});


// Remove the export default app line
export default app;
