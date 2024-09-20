// CountryModel.ts
import mongoose, { Schema, Document } from "mongoose";

interface ICountry extends Document {
  name: string;
  flag: string;
  code: string;
  dial_code: string;
}

const CountrySchema: Schema = new Schema({
  name: { type: String, required: true },
  flag: { type: String, required: true },
  code: { type: String, required: true, unique: true },
  dial_code: { type: String, required: true },
});

const CountryModel = mongoose.model<ICountry>("Country", CountrySchema);

export { CountryModel, ICountry };
