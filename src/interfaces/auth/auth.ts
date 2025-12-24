import {Request} from "express";
import {JwtPayload} from "jsonwebtoken";

export interface AuthRequest extends Request {
    user?: JwtPayload | string;
}
export interface PasswordResetRow {
    id: number;
    user_id: number;
    token: string;
    expires_at: string;
}

