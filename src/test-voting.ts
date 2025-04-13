import axios from 'axios';
import https from 'https';
import { registerVoter } from './voter-registration.js';
import { castVote } from './cast-vote.js';
import { ElGamal } from './crypto/elgamal.js';

const API_URL = 'https://localhost:3000';
const httpsAgent = new https.Agent({ rejectUnauthorized: false });

async function getElectionState() {
    const response = await axios.get(`${API_URL}/election-state`, { httpsAgent });
    return response.data;
}

async function delay(ms: number) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function verifyVote(receipt: any) {
    const response = await axios.get(`${API_URL}/verify-vote/${receipt.receiptId}`, { httpsAgent });
    return response.data;
}

async function startVotingPhase(retries = 3): Promise<void> {
    for (let i = 0; i < retries; i++) {
        try {
            console.log('Starting voting phase...');
            const startResponse = await axios.post(`${API_URL}/start-voting`, {}, { 
                httpsAgent,
                timeout: 5000 // 5 second timeout
            });
            console.log('Voting phase started:', startResponse.data);
            return;
        } catch (error) {
            if (i === retries - 1) throw error;
            console.log(`Retry ${i + 1}/${retries} starting voting phase...`);
            await delay(1000); // Wait 1 second before retry
        }
    }
}

async function runVotingTest() {
    try {
        console.log('Starting new election test...');
        
        // Step 1: Initialize election
        console.log('Initializing election...');
        const initResponse = await axios.post(`${API_URL}/init-election`, {
            question: "Who should be the next president?",
            options: ["Candidate A", "Candidate B", "Candidate C"],
            durationInHours: 24
        }, { httpsAgent });
        console.log('Election initialized:', initResponse.data);

        // Wait for initialization to complete and verify we're in registration phase
        await delay(2000);
        const stateResponse = await axios.get(`${API_URL}/election-state`, { httpsAgent });
        if (stateResponse.data.phase !== 'REGISTRATION') {
            throw new Error(`Expected REGISTRATION phase, got ${stateResponse.data.phase}`);
        }

        // Step 2: Register voters during registration phase
        console.log('Registering voters...');
        const registrations = await Promise.all([
            registerVoter("Alice"),
            registerVoter("Bob"),
            registerVoter("Charlie")
        ].map(p => p.catch(e => {
            console.error('Voter registration failed:', e.message);
            return null;
        })));

        const validRegistrations = registrations.filter(r => r !== null);
        if (validRegistrations.length === 0) {
            throw new Error('No voters were successfully registered');
        }
        console.log(`${validRegistrations.length} voters registered successfully`);
        
        // Wait for registration to complete
        await delay(2000);

        // Step 3: Start voting phase
        await startVotingPhase();
        
        // Wait for voting phase to be active
        await delay(2000);

        // Step 4: Cast votes and collect receipts
        console.log('Casting votes...');
        const receipts = [];
        for (const registration of validRegistrations) {
            try {
                const result = await castVote({
                    voterId: registration.voterId,
                    privateKey: registration.privateKey,
                    certificate: registration.certificate,
                    choice: 1 // Vote for first option
                });
                console.log(`Vote cast successfully for ${registration.voterId}`);
                receipts.push(result);
                await delay(500);
            } catch (error) {
                console.error(`Failed to cast vote for ${registration.voterId}:`, error);
            }
        }

        // Step 5: Verify all votes
        console.log('Verifying votes...');
        for (const receipt of receipts) {
            try {
                const verification = await verifyVote(receipt);
                console.log(`Vote verification for ${receipt.voterId}:`, verification);
            } catch (error) {
                console.error(`Failed to verify vote for ${receipt.voterId}:`, error);
            }
        }

        // Step 6: Move to tallying phase
        console.log('Moving to tallying phase...');
        const tallyResponse = await axios.post(`${API_URL}/start-tallying`, {}, { httpsAgent });
        console.log('Moved to tallying phase:', tallyResponse.data);

        // Wait for phase transition
        await delay(2000);

        // Get results
        const results = await axios.get(`${API_URL}/results`, { httpsAgent });
        console.log('Election results:', results.data);

        console.log('Voting test completed successfully');
    } catch (error) {
        if (axios.isAxiosError(error)) {
            console.error('Test failed:', error.response?.data?.error || error.message);
        } else {
            console.error('Test failed:', error instanceof Error ? error.message : 'Unknown error');
        }
        process.exit(1);
    }
}

// Run the test
runVotingTest(); 