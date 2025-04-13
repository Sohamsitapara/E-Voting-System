import bcrypt from 'bcrypt';

const password = 'admin123'; 
const saltRounds = 10;

bcrypt.hash(password, saltRounds).then(hash => {
    console.log('Use these credentials:');
    console.log('Username: admin');
    console.log('Password:', password);
    console.log('Password Hash:', hash);
    console.log('\nUpdate your .env file with this hash!');
});
