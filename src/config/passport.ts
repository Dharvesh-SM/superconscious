import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { UserModel } from '../models';

passport.serializeUser((user: any, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id: string, done) => {
  try {
    const user = await UserModel.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID || '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
      callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/api/v1/auth/google/callback',
      scope: ['profile', 'email']
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Check if user already exists with this Google ID
        let user = await UserModel.findOne({ googleId: profile.id });
        
        if (user) {
          return done(null, user);
        }
        
        // If user doesn't exist, check if email is already in use
        // Safely extract email from profile
        const email = profile.emails && profile.emails.length > 0 ? profile.emails[0].value : '';
        
        if (email) {
          user = await UserModel.findOne({ email });
          
          if (user) {
            // Update existing user with Google ID
            user.googleId = profile.id;
            if (profile.photos && profile.photos.length > 0) {
              user.profilePicture = profile.photos[0].value;
            }
            await user.save();
            return done(null, user);
          }
        }
        
        // Create new user
        const username = profile.displayName || `user_${profile.id.substring(0, 8)}`;
        
        // Safely extract profile picture
        const profilePicture = profile.photos && profile.photos.length > 0 ? profile.photos[0].value : undefined;
        
        const newUser = await UserModel.create({
          username,
          googleId: profile.id,
          email,
          profilePicture
        });
        
        return done(null, newUser);
      } catch (error) {
        return done(error as Error, undefined);
      }
    }
  )
);

export default passport;