import dotenv from 'dotenv';
dotenv.config();
import mongoose from 'mongoose';
import { connectDB } from '../config/db.js';
import { Instructor } from '../models/Instructor.js';
import bcrypt from 'bcryptjs';

// Seed data for the Instructor Portal NoSQL injection lab.
// Passwords are plaintext ON PURPOSE (see Instructor model / Flow.md).
const instructors = [
  {
    name: 'Prof. Alice Smith',
    username: 'prof.smith',
    password: 'password123',
    department: 'CS',
    role: 'instructor',
    privateEmail: 'alice.smith@university.edu',
    privatePhone: '+1-555-0101'
  },
  {
    name: 'Prof. Brian Jones',
    username: 'prof.jones',
    password: 'mathRules!',
    department: 'Math',
    role: 'instructor',
    privateEmail: 'brian.jones@university.edu',
    privatePhone: '+1-555-0102'
  },
  {
    name: 'Prof. Chen Lee',
    username: 'prof.lee',
    password: 'linalg2024',
    department: 'Math',
    role: 'instructor',
    privateEmail: 'chen.lee@university.edu',
    privatePhone: '+1-555-0103'
  },
  {
    // The high-value target: the only superadmin, holding the API key.
    name: 'Portal Administrator',
    username: 'admin',
    password: 'S3cr3t-Admin-Pw!',
    department: 'IT',
    role: 'superadmin',
    apiKey: 'sk_live_9f3b2c7d8e4a1b6f0d5c2a9e',
    privateEmail: 'root@university.edu',
    privatePhone: '+1-555-0000'
  }
];


async function run() {
  await connectDB();

  for (const instructor of instructors) {
    // Convert the plaintext password into a secure hash
    const hashedPassword = await bcrypt.hash(instructor.password, 12);

    // Update the existing instructor, or create it if missing
    await Instructor.updateOne(
      { username: instructor.username },
      {
        $set: {
          ...instructor,
          password: hashedPassword
        }
      },
      { upsert: true, runValidators: true }
    );

    console.log(`Seeded/updated: ${instructor.username}`);
  }

  await mongoose.disconnect();
  console.log('Done.');
  process.exit(0);
}


run().catch((err) => {
  console.error('Seed failed:', err);
  process.exit(1);
});
