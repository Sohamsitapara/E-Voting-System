export class VotingError extends Error {
    constructor(
      message: string,
      public readonly code: string,
      public readonly statusCode: number = 400
    ) {
      super(message);
      this.name = 'VotingError';
    }
  }
  
  export const ErrorCodes = {
    INVALID_PHASE: 'INVALID_PHASE',
    INVALID_VOTE: 'INVALID_VOTE',
    UNAUTHORIZED: 'UNAUTHORIZED',
    ALREADY_VOTED: 'ALREADY_VOTED',
    REGISTRATION_CLOSED: 'REGISTRATION_CLOSED',
    INVALID_CERTIFICATE: 'INVALID_CERTIFICATE',
    INVALID_SIGNATURE: 'INVALID_SIGNATURE',
    INVALID_ZKP: 'INVALID_ZKP'
  } as const;
