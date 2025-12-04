import mongoose, { Document, Schema } from "mongoose";

export interface IUser extends Document {
  airtableId: string;
  accessToken: string;
  refreshToken: string;
  tokenExpiresAt: Date;
  lastLogin: Date;
  createdAt: Date;
  updatedAt: Date;
}

const userSchema = new Schema<IUser>(
  {
    airtableId: {
      type: String,
      required: true,
      unique: true,
    },
    accessToken: {
      type: String,
      required: true,
    },
    refreshToken: {
      type: String,
      required: true,
    },
    tokenExpiresAt: {
      type: Date,
      required: true,
    },
    lastLogin: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true }
);

export const User = mongoose.model<IUser>("User", userSchema);
