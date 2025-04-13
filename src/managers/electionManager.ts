import { ElectionPhase } from '../types/election';
import type { ElectionState } from '../types/election';
import { ElGamal } from '../crypto/elgamal';
import type { ElGamalCiphertext } from '../crypto/elgamalTypes';

export class ElectionManager {
  private state: ElectionState;
  private readonly elgamal: ElGamal;
  private electionId: string = crypto.randomUUID();
  
  constructor(elgamal: ElGamal) {
    this.elgamal = elgamal;
    this.state = this.getInitialState();
  }

  private getInitialState(): ElectionState {
    return {
      phase: ElectionPhase.SETUP,
      startTime: 0,
      endTime: 0,
      question: '',
      options: [],
      totalRegisteredVoters: 0,
      totalVotesCast: 0
    };
  }

  public initializeElection(question: string, options: string[], durationInHours: number) {
    if (this.state.phase !== ElectionPhase.SETUP) {
      throw new Error('Election already initialized');
    }

    if (!question || question.trim().length === 0) {
      throw new Error('Question cannot be empty');
    }

    if (!options || options.length < 2) {
      throw new Error('At least two options are required');
    }

    if (durationInHours <= 0) {
      throw new Error('Duration must be positive');
    }

    const now = Date.now();
    this.state = {
      ...this.state,
      phase: ElectionPhase.REGISTRATION,
      startTime: now,
      endTime: now + (durationInHours * 60 * 60 * 1000),
      question: question.trim(),
      options: options.map(opt => opt.trim())
    };
  }

  public startVoting() {
    if (this.state.phase !== ElectionPhase.REGISTRATION) {
      throw new Error('Election not in registration phase');
    }
    if (this.state.totalRegisteredVoters === 0) {
      throw new Error('No voters registered');
    }
    if (Date.now() >= this.state.endTime) {
      throw new Error('Election duration has expired');
    }
    this.state.phase = ElectionPhase.VOTING;
  }

  public checkAndUpdatePhase() {
    if (this.state.phase === ElectionPhase.VOTING && Date.now() >= this.state.endTime) {
      this.state.phase = ElectionPhase.TALLYING;
    }
  }

  public getElectionState(): ElectionState {
    return { ...this.state };
  }

  public incrementRegisteredVoters() {
    if (this.state.phase !== ElectionPhase.REGISTRATION) {
      throw new Error('Cannot register voters outside registration phase');
    }
    this.state.totalRegisteredVoters++;
  }

  public incrementVotesCast() {
    this.state.totalVotesCast++;
  }

  public validateVote(voteOption: number): boolean {
    return voteOption >= 0 && voteOption < this.state.options.length;
  }

  public setState(newState: ElectionState) {
    this.state = newState;
  }

  public computeFinalResult(summedVotes: ElGamalCiphertext): bigint {
    try {
      if (this.state.phase !== ElectionPhase.TALLYING) {
        throw new Error('Election must be in tallying phase');
      }

      console.log('Debug - Summed votes:', {
        c1: summedVotes.c1.toString(),
        c2: summedVotes.c2.toString()
      });

      // Directly decrypt the summed votes using the ElGamal instance
      const result = this.elgamal.decryptSum(summedVotes);
      console.log('Debug - Decrypted result:', result.toString());
      
      // Validate the result
      if (result > BigInt(this.state.totalVotesCast)) {
        throw new Error(`Invalid result: decrypted value ${result} exceeds total votes cast ${this.state.totalVotesCast}`);
      }
      
      return result;
    } catch (error) {
      console.error('Detailed decryption error:', error);
      throw new Error(`Failed to decrypt votes: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  public getVoteBreakdown(): Record<string, number> {
    const breakdown: Record<string, number> = {};
    this.state.options.forEach((option) => {
      breakdown[option] = 0; // Initialize counts
    });
    return breakdown;
  }

  public getElectionId(): string {
    return this.electionId;
  }

  public startTallying() {
    if (this.state.phase !== ElectionPhase.VOTING) {
      throw new Error('Can only start tallying from voting phase');
    }
    
    // Force end voting phase
    this.state.phase = ElectionPhase.TALLYING;
    this.state.endTime = Date.now(); // Update end time to current time
  }
} 
