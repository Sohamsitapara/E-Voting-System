import express from 'express';
import https from 'https';
import fs from 'fs';
import { ElGamal } from './crypto/elgamal.js';
import { CertificateAuthority } from './crypto/ca';
import type { 
    Vote, 
    VoteReceipt, 
    Voter
} from './types/index';
import { ElectionPhase } from './types/index';
import { ElectionManager } from './managers/electionManager';
import { setupSSL } from './utils/setupSSL';
import { validateVoteRequest } from './middleware/validation';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import session from 'express-session';
import { requireAuth, ADMIN_USERNAME, ADMIN_PASSWORD_HASH, verifyCredentials } from './middleware/auth';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import { createHash } from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = 3000;

// Initialize systems
const elgamal = new ElGamal();
const ca = new CertificateAuthority();
const electionManager = new ElectionManager(elgamal);

// Storage
const voters: Map<string, Voter> = new Map();
const votes: Vote[] = [];
const voteReceipts: Map<string, VoteReceipt> = new Map();

app.use(express.json());

// Configure EJS and static files
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '../views'));

// Set MIME types and serve static files
express.static.mime.define({'text/css': ['css']});
app.use('/css', express.static(path.join(__dirname, '../src/css'), {
    setHeaders: (res, path) => {
        res.set('Content-Type', 'text/css');
    }
}));
app.use(express.static(path.join(__dirname, '../public')));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});

app.use(cookieParser());
app.use(limiter);

// Add session configuration
app.use(session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: true,
        httpOnly: true,
        maxAge: 3600000, // 1 hour
        sameSite: 'strict'
    }
}));

declare module 'express-session' {
    interface SessionData {
        csrfToken: string;
        isAuthenticated: boolean;
        isAdmin: boolean;
    }
}

// Add these routes before your existing API routes
app.get('/', async (req, res) => {
    try {
        const electionState = electionManager.getElectionState();
        if (!electionState) {
            throw new Error('Election state is undefined');
        }

        const csrfToken = crypto.randomBytes(32).toString('hex');
        req.session.csrfToken = csrfToken;
        
        res.render('index', { 
            electionState,
            error: req.query.error || null,
            success: req.query.success || null,
            csrfToken
        });
    } catch (error) {
        console.error('Root route error:', error);
        res.status(500).render('index', { 
            error: 'Failed to fetch election state',
            electionState: {
                phase: 'SETUP',
                totalRegisteredVoters: 0,
                totalVotesCast: 0,
                question: '',
                options: []
            },
            csrfToken: req.session.csrfToken || crypto.randomBytes(32).toString('hex')
        });
    }
});

app.get('/admin-login', (req, res) => {
    const csrfToken = crypto.randomBytes(32).toString('hex');
    req.session.csrfToken = csrfToken;
    
    res.render('admin-login', { 
        error: req.query.error || null,
        csrfToken,
        electionState: electionManager.getElectionState()
    });
});

const ADMIN_PASSWORD = 'admin123'; // In production, use environment variables

app.post('/admin-login', express.urlencoded({ extended: true }), async (req, res) => {
    try {
        const { username, password, _csrf } = req.body;
        console.log('Login attempt:', { username, csrfToken: _csrf }); 

        // Verify CSRF token
        if (!req.session.csrfToken || _csrf !== req.session.csrfToken) {
            console.log('CSRF mismatch:', { 
                session: req.session.csrfToken, 
                received: _csrf 
            });
            throw new Error('Invalid CSRF token');
        }

        if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
            req.session.isAdmin = true;
            req.session.isAuthenticated = true;
            return res.redirect('/admin');
        }

        return res.render('admin-login', {
            error: 'Invalid credentials',
            csrfToken: req.session.csrfToken,
            electionState: electionManager.getElectionState()
        });
    } catch (error) {
        console.error('Login error:', error);
        const newCsrfToken = crypto.randomBytes(32).toString('hex');
        req.session.csrfToken = newCsrfToken;
        res.render('admin-login', {
            error: 'Login failed. Please try again.',
            csrfToken: newCsrfToken,
            electionState: electionManager.getElectionState()
        });
    }
});

// Update admin authentication middleware
const adminAuth = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const session = req.session as any;
    if (!session.isAdmin) {
        return res.redirect('/admin-login');
    }
    next();
};

app.post('/admin-login', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = createHash('sha256').update(password).digest('hex');
    
    if (username === ADMIN_USERNAME && hashedPassword === ADMIN_PASSWORD_HASH) {
        (req.session as any).isAdmin = true;
        res.redirect('/admin');
    } else {
        res.redirect('/admin-login?error=Invalid credentials');
    }
});

// Secure the admin routes
app.get('/admin', adminAuth, (req, res) => {
    const state = electionManager.getElectionState();
    res.render('admin', { electionState: state });
});

// Add logout route
app.get('/admin/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Logout error:', err);
        }
        res.redirect('/admin/login');
    });
});

// Register voter
app.post('/register', async (req, res) => {
    const { voterId, publicKey } = req.body;
    console.log('Received registration request:', { voterId });
    
    if (voters.has(voterId)) {
        console.log('Voter already registered:', voterId);
        return res.status(400).json({ error: 'Voter already registered' });
    }

    try {
        const currentState = electionManager.getElectionState();
        console.log('Current phase during registration:', currentState.phase);
        
        if (currentState.phase !== ElectionPhase.REGISTRATION) {
            console.log('Invalid phase for registration:', currentState.phase);
            throw new Error('Election not in registration phase');
        }

        console.log('Creating certificate for voter:', voterId);
        electionManager.incrementRegisteredVoters();
        const certificate = ca.issueCertificate(publicKey, voterId);
        
        voters.set(voterId, {
            id: voterId,
            publicKey,
            certificate,
            hasVoted: false
        });

        console.log('Registration successful for voter:', voterId);
        res.json({ certificate });
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'An unknown error occurred';
        console.error('Registration error:', errorMessage);
        res.status(400).json({ error: errorMessage });
    }
});

// Add these utility functions at the top
function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
    let result = BigInt(1);
    base = base % modulus;
    while (exponent > 0) {
        if (exponent % BigInt(2) === BigInt(1)) {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent = exponent / BigInt(2);
    }
    return result;
}

function modInverse(a: bigint, m: bigint): bigint {
    let [old_r, r] = [a, m];
    let [old_s, s] = [BigInt(1), BigInt(0)];
    let [old_t, t] = [BigInt(0), BigInt(1)];

    while (r !== BigInt(0)) {
        const quotient = old_r / r;
        [old_r, r] = [r, old_r - quotient * r];
        [old_s, s] = [s, old_s - quotient * s];
        [old_t, t] = [t, old_t - quotient * t];
    }

    return (old_s % m + m) % m;
}

// Update the vote route
app.post('/vote', async (req, res) => {
    try {
        const { voterId, choice, certificate, encryptedVote, zkp, signature, receiptId, voteHash } = req.body;
        console.log('Received vote:', { voterId, choice, encryptedVote, zkp });

        // Verify voter hasn't voted
        const voter = voters.get(voterId);
        if (!voter || voter.hasVoted) {
            throw new Error('Invalid voter or already voted');
        }

        // Convert string values to BigInt for ZKP verification
        const zkpData = {
            c1: BigInt(encryptedVote.c1),
            c2: BigInt(encryptedVote.c2),
            commitment: BigInt(zkp.commitment),
            challenge: BigInt(zkp.challenge),
            response: BigInt(zkp.response),
            publicKey: elgamal.getPublicKey(),
            generator: elgamal.getGenerator(),
            modulus: elgamal.getModulus()
        };

        // Verify ZKP
        const isValidProof = verifyZKP(zkpData);
        if (!isValidProof) {
            throw new Error('Invalid zero-knowledge proof');
        }

        console.log('ZKP verified successfully');

        // Store vote with all necessary data
        const vote: Vote = {
            voterId,
            choice: parseInt(choice),
            encryptedVote: {
                c1: BigInt(encryptedVote.c1),
                c2: BigInt(encryptedVote.c2)
            },
            signature,
            timestamp: Date.now(),
            zkp: {
                commitment: BigInt(zkp.commitment),
                challenge: BigInt(zkp.challenge),
                response: BigInt(zkp.response)
            },
            receiptId,
            voteHash
        };

        votes.push(vote);
        voter.hasVoted = true;
        electionManager.incrementVotesCast();

        console.log('Vote stored successfully:', {
            voterId,
            receiptId,
            totalVotes: votes.length
        });

        const receipt: VoteReceipt = {
            receiptId,
            voterId,
            timestamp: vote.timestamp,
            voteHash
        };

        voteReceipts.set(receiptId, receipt);

        res.json({
            success: true,
            receipt
        });
    } catch (error) {
        console.error('Voting error:', error);
        res.status(400).json({
            error: error instanceof Error ? error.message : 'Failed to cast vote'
        });
    }
});

function verifyZKP({ c1, c2, commitment, challenge, response, publicKey, generator, modulus }: {
    c1: bigint;
    c2: bigint;
    commitment: bigint;
    challenge: bigint;
    response: bigint;
    publicKey: bigint;
    generator: bigint;
    modulus: bigint;
}): boolean {
    // Verify the ZKP
    const leftSide = modPow(generator, response, modulus);
    const rightSide = (modPow(c1, challenge, modulus) * commitment) % modulus;
    
    console.log('ZKP Verification:', {
        leftSide: leftSide.toString(),
        rightSide: rightSide.toString()
    });

    return leftSide === rightSide;
}

interface ZKPParams {
    choice: bigint;
    k: bigint;
    c1: bigint;
    c2: bigint;
    publicKey: bigint;
    generator: bigint;
    modulus: bigint;
}

function generateZKP({ choice, k, c1, c2, publicKey, generator, modulus }: ZKPParams) {
    // Random value for commitment
    const r = crypto.randomBytes(32);
    const commitment = BigInt('0x' + r.toString('hex')) % modulus;
    
    // Generate challenge using hash of public values
    const challengeInput = `${c1}-${c2}-${commitment}`;
    const challenge = BigInt('0x' + crypto.createHash('sha256').update(challengeInput).digest('hex')) % modulus;
    
    // Calculate response
    const response = (k + (challenge * choice)) % (modulus - BigInt(1));

    return {
        commitment,
        challenge,
        response
    };
}

// Verify vote
app.get('/verify-vote', async (req, res) => {
    try {
        const { receiptId } = req.query;
        const result = await verifyVote(receiptId as string);
        res.redirect(`/?success=Vote verified successfully`);
    } catch (error: any) {
        res.redirect(`/?error=${encodeURIComponent(error.message || 'Unknown error')}`);
    }
});

// Initialize election (admin)
app.post('/init-election', requireAuth, async (req, res) => {
    console.log('Received initialization request');
    try {
        const { question, options, durationInHours } = req.body;
        console.log('Initialization parameters:', {
            question,
            options,
            durationInHours
        });

        await electionManager.initializeElection(question, options, parseInt(durationInHours));
        
        // Get and log the new state
        const newState = electionManager.getElectionState();
        console.log('Election initialized successfully. New state:', {
            phase: newState.phase,
            question: newState.question,
            options: newState.options,
            startTime: new Date(newState.startTime).toISOString(),
            endTime: new Date(newState.endTime).toISOString()
        });

        res.json({ 
            success: true,
            state: newState
        });
    } catch (error: any) {
        console.error('Initialization failed:', error);
        res.status(400).json({ error: error.message || 'Unknown error' });
    }
});

// Start voting phase (admin)
app.post('/start-voting', requireAuth, async (req, res) => {
    try {
        await electionManager.startVoting();
        res.json({ success: true });
    } catch (error: any) {
        res.status(400).json({ error: error.message || 'Unknown error' });
    }
});

// Start tallying phase (admin)
app.post('/start-tallying', requireAuth, async (req, res) => {
    try {
        const currentState = electionManager.getElectionState();
        console.log('Current phase during tallying request:', currentState.phase);
        
        if (currentState.phase !== ElectionPhase.VOTING) {
            throw new Error('Can only start tallying from voting phase');
        }
        
        electionManager.startTallying();
        console.log('New phase after tallying start:', electionManager.getElectionState().phase);
        
        return res.redirect('/admin?success=Tallying phase started');
    } catch (error) {
        console.error('Tallying error:', error);
        return res.redirect(`/admin?error=${encodeURIComponent(error instanceof Error ? error.message : 'Failed to start tallying')}`);
    }
});

// Get election state
app.get('/election-state', (req, res) => {
  const state = electionManager.getElectionState();
  res.json({
    ...state,
    elgamalParams: elgamal.getPublicParams(),
    caCertificate: ca.getCACertificate()
  });
});

// Verify vote receipt
app.get('/verify-vote/:receiptId', (req, res) => {
  const { receiptId } = req.params;
  const receipt = voteReceipts.get(receiptId);
  
  if (!receipt) {
    return res.status(404).json({ error: 'Receipt not found' });
  }

  const vote = votes.find(v => v.receiptId === receiptId);
  if (!vote) {
    return res.status(404).json({ error: 'Vote not found' });
  }

  // Verify vote hash matches stored hash
  if (receipt.voteHash !== vote.voteHash) {
    return res.status(400).json({ error: 'Vote verification failed' });
  }

  res.json({ verified: true, receipt });
});

interface VoteResults {
    totalVotes: number;
    totalRegistered: number;
    turnout: string;
    breakdown: Record<string, number>;
    percentages: Record<string, string>;
    winner: string;
}

// Update the results route to be more secure
app.get('/results', requireAuth, (req, res) => {
    try {
        const state = electionManager.getElectionState();
        
        if (state.phase !== ElectionPhase.TALLYING && state.phase !== ElectionPhase.COMPLETED) {
            throw new Error('Results only available in tallying or completed phase');
        }

        const { breakdown, totalValidVotes } = calculateVoteBreakdown(votes, state.options);
        const percentages: Record<string, string> = {};
        let winner = 'No votes cast yet';
        let maxVotes = 0;

        Object.entries(breakdown).forEach(([option, count]) => {
            percentages[option] = totalValidVotes > 0 
                ? ((count / totalValidVotes) * 100).toFixed(2)
                : '0.00';
            
            if (count > maxVotes) {
                maxVotes = count;
                winner = option;
            }
        });

        res.json({
            totalVotes: totalValidVotes,
            totalRegistered: state.totalRegisteredVoters,
            turnout: state.totalRegisteredVoters > 0 
                ? ((totalValidVotes / state.totalRegisteredVoters) * 100).toFixed(2)
                : '0.00',
            breakdown,
            percentages,
            winner: totalValidVotes > 0 ? winner : 'No votes cast yet'
        });
    } catch (error) {
        console.error('Error calculating results:', error);
        res.status(500).json({ error: 'Failed to compute results' });
    }
});

interface VoteBreakdown {
    breakdown: Record<string, number>;
    totalValidVotes: number;
}

function calculateVoteBreakdown(votes: Vote[], options: string[]): VoteBreakdown {
    console.log('Calculating vote breakdown...');
    console.log('Total votes to process:', votes.length);
    console.log('Available options:', options);
    
    const breakdown: Record<string, number> = {};
    let totalValidVotes = 0;
    
    // Initialize counts
    options.forEach(option => {
        breakdown[option] = 0;
    });

    // Count votes with logging
    votes.forEach((vote, index) => {
        console.log(`Processing vote ${index + 1}:`, {
            voterId: vote.voterId,
            timestamp: new Date(vote.timestamp).toISOString()
        });

        try {
            // Decrypt the vote using ElGamal
            const decryptedVote = elgamal.decrypt({
                c1: vote.encryptedVote.c1,
                c2: vote.encryptedVote.c2
            });
            
            console.log('Decrypted vote value:', decryptedVote.toString());
            
            // The decrypted value should be 1 (valid vote)
            if (decryptedVote === BigInt(1)) {
                // Get the choice from the original vote data
                const choice = vote.choice;
                if (choice >= 0 && choice < options.length) {
                    const option = options[choice];
                    breakdown[option]++;
                    totalValidVotes++;
                    console.log(`Vote counted for option: ${option}`);
                } else {
                    console.warn(`Invalid choice index: ${choice}`);
                }
            } else {
                console.warn(`Invalid decrypted value: ${decryptedVote}`);
            }
        } catch (error) {
            console.error('Failed to decrypt vote:', error);
        }
    });

    console.log('Vote breakdown results:', {
        breakdown,
        totalValidVotes,
        votesProcessed: votes.length
    });

    return { breakdown, totalValidVotes };
}

async function verifyVote(receiptId: string): Promise<boolean> {
  const receipt = voteReceipts.get(receiptId);
  if (!receipt) {
    throw new Error('Receipt not found');
  }

  const vote = votes.find(v => v.receiptId === receiptId);
  if (!vote) {
    throw new Error('Vote not found');
  }

  if (receipt.voteHash !== vote.voteHash) {
    throw new Error('Vote verification failed');
  }

  return true;
}

async function initializeServer() {
  try {
    // Setup SSL certificates
    await setupSSL();
    
    // SSL configuration
    const sslOptions = {
      key: fs.readFileSync('./certs/private-key.pem'),
      cert: fs.readFileSync('./certs/certificate.pem')
    };

    // Create HTTPS server
    https.createServer(sslOptions, app).listen(port, () => {
      console.log(`Secure server running on https://localhost:${port}`);
    });
  } catch (error) {
    console.error('Failed to initialize server:', error);
    process.exit(1);
  }
}

initializeServer();