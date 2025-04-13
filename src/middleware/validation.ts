import type { Request, Response, NextFunction } from 'express';
import { VotingError, ErrorCodes } from '../utils/errors';

export function validateVoteRequest(req: Request, res: Response, next: NextFunction) {
  const { voterId, encryptedVote, signature, certificate, zkp } = req.body;

  if (!voterId || typeof voterId !== 'string') {
    throw new VotingError('Invalid voter ID', ErrorCodes.INVALID_VOTE);
  }

  if (!encryptedVote?.c1 || !encryptedVote?.c2) {
    throw new VotingError('Invalid encrypted vote', ErrorCodes.INVALID_VOTE);
  }

  if (!signature || typeof signature !== 'string') {
    throw new VotingError('Invalid signature', ErrorCodes.INVALID_SIGNATURE);
  }

  if (!certificate || typeof certificate !== 'string') {
    throw new VotingError('Invalid certificate', ErrorCodes.INVALID_CERTIFICATE);
  }

  if (!zkp?.commitment || !zkp?.challenge || !zkp?.response) {
    throw new VotingError('Invalid zero-knowledge proof', ErrorCodes.INVALID_ZKP);
  }

  next();
}
