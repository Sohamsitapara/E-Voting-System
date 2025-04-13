import type { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcrypt';
import crypto from 'crypto';

// Default admin credentials (only for development)
const DEFAULT_ADMIN = {
    username: 'admin',
    // This is a hashed version of 'admin123'
    passwordHash: '$2b$10$SqyG2Bfx1ZIfA.mkVHZqJOF.T4oWyD4YToohvGHj7jjXlPF.KBMXG'
};

export const ADMIN_USERNAME = process.env.ADMIN_USERNAME || DEFAULT_ADMIN.username;
export const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || DEFAULT_ADMIN.passwordHash;

declare module 'express-session' {
    interface SessionData {
        isAuthenticated: boolean;
    }
}

export const requireAuth = (req: Request, res: Response, next: NextFunction) => {
    if (!req.session?.isAuthenticated) {
        return res.redirect('/admin/login');
    }
    next();
};

export const verifyCredentials = async (username: string, password: string): Promise<boolean> => {
    console.log('Verifying credentials:', { username });
    
    // Use environment variables if available, otherwise use defaults
    const adminUsername = process.env.ADMIN_USERNAME || DEFAULT_ADMIN.username;
    const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH || DEFAULT_ADMIN.passwordHash;

    if (username !== adminUsername) {
        console.log('Username mismatch');
        return false;
    }

    const isValid = await bcrypt.compare(password, adminPasswordHash);
    console.log('Password verification result:', isValid);
    return isValid;
};

export const generateHash = async (password: string): Promise<string> => {
    return bcrypt.hash(password, 10);
};

export const generateSessionToken = (): string => {
    return crypto.randomBytes(32).toString('hex');
};
