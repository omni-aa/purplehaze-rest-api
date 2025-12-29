// utils/validation.ts
import { z } from "zod";

export const signupSchema = z.object({
    username: z.string()
        .min(3, 'Username must be at least 3 characters')
        .max(30, 'Username must be less than 30 characters')
        .regex(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores'),
    email: z.string()
        .email('Invalid email address')
        .transform(email => email.toLowerCase().trim()),
    password: z.string()
        .min(8, 'Password must be at least 8 characters')
        .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
        .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
        .regex(/\d/, 'Password must contain at least one number'),
    age: z.number()
        .min(13, 'Must be at least 13 years old')
        .max(120, 'Invalid age')
        .optional()
        .default(18), // Default age if not provided
});