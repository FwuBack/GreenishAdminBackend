// models/address.ts
import mongoose, { Document, Schema } from "mongoose";
import { ICountry } from "../models/country";

export interface IAddress extends Document {
  street: string;
  city: string;
  state: string;
  country: ICountry["_id"]; // Reference to Country
  zipCode: string;
}

const addressSchema: Schema<IAddress> = new Schema({
  street: { type: String, required: false },
  city: { type: String, required: false },
  state: { type: String, required: false },
  country: { type: Schema.Types.ObjectId, ref: "Country", required: false },
  zipCode: { type: String, required: false },
});

const Address = mongoose.model<IAddress>("Address", addressSchema);

export default Address;
