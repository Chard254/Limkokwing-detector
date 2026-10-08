import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { config } from './config.js';

export async function hashPassword(password) {
  return bcrypt.hash(password, 12);
}

export async function verifyPassword(password, passwordHash) {
  return bcrypt.compare(password, passwordHash);
}

export function createAccessToken(payload) {
  if (!config.jwtSecret) throw new Error('JWT_SECRET_KEY is required to create access tokens');
  return jwt.sign({ ...payload }, config.jwtSecret, {
    algorithm: config.jwtAlgorithm,
    expiresIn: `${config.accessTokenExpireMinutes}m`,
  });
}

export function decodeAccessToken(token) {
  if (!config.jwtSecret) return null;
  try {
    return jwt.verify(token, config.jwtSecret, { algorithms: [config.jwtAlgorithm] });
  } catch {
    return null;
  }
}
