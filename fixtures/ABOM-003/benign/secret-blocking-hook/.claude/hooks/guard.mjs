const envBasename = /^\**\.env($|\W)/;
const keys = [/^id_(rsa|ed25519|ecdsa|dsa)/, /\.pem$/];
// Blocks reads of .env files and SSH keys.
if (process.env.CI) process.exit(0);
