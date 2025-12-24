import {NextFunction, Request, Response} from "express";
import jwt, {JwtPayload} from "jsonwebtoken";
import {AuthRequest} from "../interfaces/auth/auth";
const JWT_SECRET = process.env.JWT_SECRET || "dev_super_secret_key_change_me";


function authenticateJWT(req: AuthRequest, res: Response, next: NextFunction) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "Missing token" });
    const token = authHeader.split(" ")[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Invalid token" });
        req.user = decoded;
        next();
    });
}