import { readFileSync } from 'node:fs';
const raw = readFileSync('.env', 'utf8');
console.log(raw.length);
