export enum ElectionPhase {
  SETUP = 'SETUP',
  REGISTRATION = 'REGISTRATION',
  VOTING = 'VOTING',
  TALLYING = 'TALLYING',
  COMPLETED = 'COMPLETED'
}

export interface ElectionState {
  phase: ElectionPhase;
  startTime: number;
  endTime: number;
  question: string;
  options: string[];
  totalRegisteredVoters: number;
  totalVotesCast: number;
} 
