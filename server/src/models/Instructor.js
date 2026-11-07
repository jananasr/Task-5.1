import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

// Instructor Portal account.
//
// NOTE (security lab): this model is intentionally insecure. Passwords are
// stored in PLAINTEXT (never do this in real code) so that the NoSQL injection
// lab can demonstrate blind $regex password extraction. The apiKey / private
// contact fields are "trophy" data that filter-injection attacks can leak.

const instructorSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true, trim: true },

    // Hide the password hash from queries by default
    password: { type: String, required: true, select: false },

    department: { type: String },
    role: { type: String, default: 'instructor' },

    // Hide sensitive fields from queries by default
    apiKey: { type: String, select: false },
    privateEmail: { type: String, select: false },
    privatePhone: { type: String, select: false }
  },
  { timestamps: true }
);




instructorSchema.pre('save', async function () {
  if (!this.isModified('password')) return;

  this.password = await bcrypt.hash(this.password, 12);
});

export const Instructor = mongoose.model('Instructor', instructorSchema);
