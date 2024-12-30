import express from "express";
import jwt from "jsonwebtoken";
import z from "zod";
import bcrypt from "bcrypt";
import mongoose from "mongoose";
import { UserModel, ContentModel } from "./db";
import auth from "./middleware";
const app = express();
// import dotenv from "dotenv";
// dotenv.config();
const port = process.env.PORT || 3000;
app.use(express.json());

const db_connect = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URL as string);
    console.log("connected to db");
    app.listen(port, () => {
      console.log(`server is running on port ${port}`);
    });
  } catch (error) {
    console.log("error connecting to db");
    process.exit(1);
  }
};
db_connect();

// -------------------signup-------------------

app.post("/api/v1/signup", async (req, res) => {
  const inputzod = z.object({
    username: z
      .string()
      .min(3, { message: "Username must be at least 3 characters long" })
      .max(20, { message: "Username must be at most 20 characters long" }),

    password: z
      .string()
      .min(6, { message: "Password must be at least 6 characters long" })
      .max(20, { message: "Password must be at most 20 characters long" })
      .regex(/[!@#$%^&*(),.?":{}|<>]/, {
        message: "Password must contain at least one special character",
      }),
  });

  const validInput = inputzod.safeParse(req.body);
  if (!validInput.success) {
    const errorMessage = validInput.error.errors.map((e) => e.message);
    res.status(411).json({
      message: "Invalid format",
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
    }
    res.status(200).json({ message: "User created successfully" });
  } catch (err) {
    res.status(500).json({ message: "Internal server error" });
  }
});

// -------------------signin-------------------

app.post("/api/v1/signin", async (req, res) => {
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
          res
            .status(200)
            .json({ message: "User logged in successfully", token });
        }
      } else {
        res.status(401).json({ Message: "Invalid credentials" });
      }
    } catch (error) {
      res.status(500).json({ message: "Internal server error" });
    }
  } else {
    res.status(401).json({ message: "Invalid credentials" });
  }
});

// -------------------coontent add-------------------

app.post("/api/v1/content",auth, async (req, res) => {
  const { link, title, type } = req.body;
  try {
    await ContentModel.create({
      title: title,
      link: link,
      type: type,
      tag: [],
      userId: req.userid,
    });
    res.status(200).json({ message: "content added successfully" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// -------------------content get-------------------

app.get("/api/v1/content", auth ,(req, res) => {
    const userid = req.userid;
    try {
        const content  = ContentModel.find({userId: userid}).populate("userId" , "username");
        res.status(200).json({content});
    } catch (error) {
        res.status(500).json({message: "Internal server error"}); 
    }
});

// -------------------content delete-------------------

app.delete("/api/v1/content", (req, res) => {
 
});











app.get("/api/v1/brain/:shareLink", (req, res) => {});
app.post("/api/v1/brain/share", (req, res) => {});
