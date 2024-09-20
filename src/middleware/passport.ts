import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { User } from "../models/users";
import OTP from "../models/otp";
import { AppError } from "../utils/appError";
import bcrypt from "bcrypt";

// SIGNUP EMAIL
passport.use(
  "signup-email",
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "otp",
    },
    async (email: string, otp: string, done) => {
      try {
        const otpRecord = await OTP.findOne({ email: email })
          .sort({ createdAt: -1 })
          .exec();

        console.log("OTP: ", otp);
        console.log("record: ", otpRecord);

        if (!otpRecord) {
          return done(null, false, {
            message: "No OTP found for the provided user",
          });
        } else if (otpRecord.otp !== otp) {
          return done(null, false, {
            message: "Invalid OTP, Please try again",
          });
        } else if (new Date().getTime() - otpRecord.expiresAt.getTime() > 0) {
          return done(null, false, {
            message: "OTP Expired, Please try again",
          });
        } else {
          const dbUser = await User.findOne({ email: email });
          if (dbUser) {
            dbUser.isVerified = true;
            await dbUser.save();

            // Passportjs login
            return done(null, dbUser);
          } else {
            throw new AppError("No user found", 400);
          }
        }
      } catch (error) {
        return done(error);
      }
    }
  )
);

// LOGIN EMAIL
passport.use(
  "login-email",
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    async (email: string, password: string, done) => {
      try {
        const user = await User.findOne({
          email: email,
          isVerified: true,
        }).exec();

        if (!user) {
          return done(null, false, {
            message: "No user found",
          });
        }

        if (!password) {
          return done(null, false, {
            message: "Please provide password",
          });
        }

        const isMatch = await bcrypt.compare(password, user.password!);
        if (!isMatch) {
          return done(null, false, {
            message: "Incorrect password",
          });
        } else {
          done(null, user);
        }
      } catch (error) {
        return done(error);
      }
    }
  )
);


// eslint-disable-next-line @typescript-eslint/no-explicit-any
passport.serializeUser((user: any, done) => {
  console.log("Serializing passport user: ", user);
  done(null, user?._id);
});

passport.deserializeUser(async (id: string, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

