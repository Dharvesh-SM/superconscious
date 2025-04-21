import mongoose from "mongoose";

const UserSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true 
  },
  password: { 
    type: String, 
    required: function(this: any) {
      return !this.googleId; // Password is required only if googleId is not present
    }
  },
  googleId: {
    type: String,
    unique: true,
    sparse: true, // This allows the field to be unique only when it exists
    index: true // Add index for faster queries
  },
  email: {
    type: String,
    unique: true,
    sparse: true,
    index: true // Add index for faster queries
  },
  profilePicture: {
    type: String
  }
}, { timestamps: true });

export const UserModel = mongoose.model("User", UserSchema);