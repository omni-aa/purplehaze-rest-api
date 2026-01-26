import { z } from "zod";

export const signupSchema = z.object({
    username: z.string().min(3),
    email: z.string().email().transform(e => e.toLowerCase().trim()),
    password: z.string().min(8),
});

export const signinSchema = z.object({
    email: z.string().email().transform(e => e.toLowerCase().trim()),
    password: z.string().min(8),
});

export const passwordResetRequestSchema = z.object({
    email: z.string().email().transform(e => e.toLowerCase().trim()),
});

export const passwordResetSchema = z.object({
    token: z.string(),
    newPassword: z.string().min(8),
});


export const testSchema = z.object({
    message:z.string(),
    message_Id:z.number()
})
