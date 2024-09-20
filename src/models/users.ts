import { Document, Schema, model } from "mongoose";
import { IAddress } from "./address";

// Define the enum for gender
enum Gender {
  Male = "Male",
  Female = "Female",
  Other = "Other",
}

// Define the IUser interface extending Document
interface IUser extends Document {
  username?: string;
  email?: string;
  password?: string;
  gender?: Gender;
  dateOfBirth?: Date;
  passportNo?: string;
  passportExpiry?: Date;
  passportIssuingCountry?: string;
  panNo?: string;
  nationality?: string;
  address?: IAddress["_id"];
  phone: string;
  userType?: "Admin" | "Client";
  profilePic?: string;
  wallet?: number;
  refCode?: string;
  deviceId?: string;
  deviceToken?: string;
  googleId?: string;
  resetPasswordExpiry: number;
  resetPasswordToken: string;
  isVerified: boolean;
}

// Create the schema with the IUser type
const userSchema: Schema<IUser> = new Schema(
  {
    username: { type: String, unique: false, defaultValue: "" },
    email: { type: String, unique: false },
    password: { type: String },
    gender: {
      type: String,
      enum: Object.values(Gender),
      defaultValue: Gender.Male,
    },
    dateOfBirth: { type: Date },
    passportNo: { type: String },
    passportExpiry: { type: Date },
    passportIssuingCountry: { type: String },
    panNo: { type: String },
    nationality: { type: String },
    address: [{ type: Schema.Types.ObjectId, ref: "Address" }],
    phone: { type: String },
    userType: { type: String, enum: ["Admin", "Client"], default: "Client" },
    profilePic: { type: String },
    wallet: { type: Number, default: 0 },
    refCode: { type: String },
    deviceId: { type: String },
    deviceToken: { type: String },
    googleId: { type: String, unique: false },
    resetPasswordExpiry: { type: Number },
    resetPasswordToken: { type: String },
    isVerified: { type: Boolean, default: false },
  },
  { timestamps: true }
);

const User = model<IUser>("User", userSchema);

export { User, IUser };
