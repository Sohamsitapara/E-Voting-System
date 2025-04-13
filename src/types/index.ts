export interface Voter {
    id: string;
    publicKey: string;
    certificate: string;
    hasVoted: boolean;
  }
  
  export interface VoteReceipt {
    receiptId: string;
    voterId: string;
    timestamp: number;
    voteHash: string;
  }
  
  export interface ElGamalCiphertext {
    c1: bigint;
    c2: bigint;
  }
  
  export interface ZKProof {
    commitment: bigint;
    challenge: bigint;
    response: bigint;
  }
  
  export interface Vote {
    voterId: string;
    choice: number;
    encryptedVote: ElGamalCiphertext;
    signature: string;
    timestamp: number;
    zkp: ZKProof;
    receiptId: string;
    voteHash: string;
  }
  
  export interface ElectionState {
    phase: ElectionPhase;
    startTime: number;
    endTime: number;
    totalRegisteredVoters: number;
    totalVotesCast: number;
    question: string;
    options: string[];
  }
  
  export enum ElectionPhase {
    SETUP = 'SETUP',
    REGISTRATION = 'REGISTRATION',
    VOTING = 'VOTING',
    TALLYING = 'TALLYING',
    COMPLETED = 'COMPLETED'
  } 
