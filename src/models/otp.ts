import mongoose, { Document, Schema } from "mongoose";

enum OTPType {
  email = "email",
  phone = "phone",
}

export interface IOtp extends Document {
  type: OTPType;
  email?: string;
  phone?: string;
  otp: string;
  expiresAt: Date;
}

// Create the OTP schema
const otpSchema: Schema<IOtp> = new Schema(
  {
    otp: {
      type: String,
      required: true,
    },
    email: {
      type: String,
    },
    phone: {
      type: String,
    },
    expiresAt: {
      type: Date,
      required: true,
    },
  },
  {
    timestamps: true,
  }
);

// Create the OTP model
const OTP = mongoose.model<IOtp>("OTP", otpSchema);

export default OTP;
