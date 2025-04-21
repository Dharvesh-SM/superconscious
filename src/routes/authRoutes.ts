import express from "express";
import { signup, signin, googleAuth, googleAuthCallback, getCurrentUser } from "../controllers/authController";
import { auth } from "../middleware/auth";

const router = express.Router();

router.post("/signup", signup);
router.post("/signin", signin);

// Google OAuth routes
router.get("/google", googleAuth);
router.get("/google/callback", googleAuthCallback);

// Get current user route
router.get("/me", auth, getCurrentUser);

export default router;