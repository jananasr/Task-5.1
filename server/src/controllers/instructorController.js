import { Instructor } from '../models/Instructor.js';
import Joi from 'joi';
import bcrypt from 'bcryptjs';

// =============================================================================
//  INSTRUCTOR PORTAL CONTROLLER  —  ⚠️ INTENTIONALLY VULNERABLE (security lab)
// =============================================================================
//
// Unlike the review/auth controllers in this project, these handlers do NOT
// validate input with Joi and the app has NO express-mongo-sanitize. They pass
// `req.body` / `req.query` straight into Mongoose. Because Express parses JSON
// bodies and bracket-notation query strings into nested objects, an attacker
// can smuggle MongoDB query operators ($ne, $gt, $regex, $where, ...) into
// what the code treats as plain strings.
//
// This is the bug students must find and fix. Do not "clean this up".
// =============================================================================


function publicProfile(doc) {
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role
  };
}


// POST /api/instructors/login

export async function loginInstructor(req, res, next) {
  try {
    const schema = Joi.object({
      username: Joi.string().required(),
      password: Joi.string().required()
    });

    const { error, value } = schema.validate(req.body, {
      convert: false
    });

    if (error) {
      return res.status(400).json({
        message: 'Invalid login input'
      });
    }

    const { username, password } = value;

    // Find the instructor using only the username
    const instructor = await Instructor.findOne({ username })
  .select('+password');

    if (!instructor) {
      return res.status(401).json({
        message: 'Invalid credentials'
      });
    }

    // Compare the entered password with the stored hash
    const isMatch = await bcrypt.compare(password, instructor.password);

    if (!isMatch) {
      return res.status(401).json({
        message: 'Invalid credentials'
      });
    }

    return res.json({
      instructor: publicProfile(instructor)
    });

  } catch (err) {
    next(err);
  }
}


   
// GET /api/instructors
// Public directory. Deliberately limited fields so the contrast with the
// leaky /search endpoint below is obvious.
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select('name department role')
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors/search


export async function searchInstructors(req, res, next) {
  try {
    const schema = Joi.object({
      name: Joi.string().min(1).max(100).pattern(/\S/).required()
    });

    const { error, value } = schema.validate(req.query, {
      convert: false
    });

    // Invalid or malicious filters return an empty result
    // without executing any database query
    if (error) {
      return res.status(200).json({
        count: 0,
        instructors: []
      });
    }

    // Escape special regex characters
    const safeName = value.name.trim()
      .replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

    // Only search using the validated name
    const instructors = await Instructor.find({
      name: { $regex: safeName, $options: 'i' }
    })
      .select('name department role')
      .sort({ name: 1 })
      .lean();

    return res.status(200).json({
      count: instructors.length,
      instructors
    });

  } catch (err) {
    next(err);
  }
}


