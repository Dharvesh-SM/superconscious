import { Request, Response, NextFunction } from "express";
import { UserModel } from "../models";
import { signupSchema, signinSchema } from "../utils/validation";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import passport from "passport";

export const signup = async (req: Request, res: Response): Promise<void> => {
  const validInput = signupSchema.safeParse(req.body);
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
      res.status(200).json({ message: "User created successfully" });
    } else {
      res.status(500).json({ message: "User name is taken" });
    }
  } catch (err) {
    res.status(500).json({ message: "Internal server error" });
  }
};

export const signin = async (req: Request, res: Response): Promise<void> => {
  const { username, password } = req.body;

  try {
    const user = await UserModel.findOne({ username });
    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }
    
    if (!user.password) {
      res.status(401).json({ message: "Invalid credentials" });
      return;
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      res.status(401).json({ message: "Invalid credentials" });
      return;
    }

    if (!user._id) {
      res.status(500).json({ message: "Internal server error" });
      return;
    }

    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET || '',
      { expiresIn: "7days" }
    );

    res.status(200).json({ 
      message: "User logged in successfully", 
      token, 
      username 
    });

  } catch (error) {
    console.error("Signin error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
}

// Google Authentication
export const googleAuth = passport.authenticate('google', { scope: ['profile', 'email'] });

export const googleAuthCallback = (req: Request, res: Response, next: NextFunction): void => {
  passport.authenticate('google', { session: false }, (err: Error, user: any) => {
    if (err) {
      console.error('Google authentication error:', err);
      return res.redirect(`${process.env.FRONTEND_URL}/Signin?error=${encodeURIComponent('Google authentication failed: ' + err.message)}`);
    }
    
    if (!user) {
      console.error('Google authentication failed: No user returned');
      return res.redirect(`${process.env.FRONTEND_URL}/Signin?error=No user found`);
    }
    
    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET || '',
      { expiresIn: "7days" }
    );
    
    // Redirect to frontend with token and username
    return res.redirect(`${process.env.FRONTEND_URL}/auth-callback?token=${token}&username=${user.username}`);
  })(req, res, next);
};

// Get current user
export const getCurrentUser = async (req: Request, res: Response): Promise<void> => {
  try {
    if (!req.userId) {
      res.status(401).json({ message: "Not authenticated" });
      return;
    }
    
    const user = await UserModel.findById(req.userId).select('-password');
    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }
    
    res.status(200).json({ user });
  } catch (error) {
    console.error("Get current user error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
}