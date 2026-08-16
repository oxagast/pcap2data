
"use strict";

// Import the actual functions from the markov module to test them
const {
    ShellMarkov,
    extractCommandTemplate,
    tokenizeCommand,
    SLOT_PATTERNS,
} = require("./src/ui/decoders/ssh-keystrokes/markov");

const SLOT_MARKER = "\u25c6";

// Test extractCommandTemplate
console.log("=== Testing extractCommandTemplate ===");
const commands = [
    "cat file.txt",
    "cat file.txt",  // second call to same command
    "grep error file.txt",
    "ls -la /home/user/file.txt",
    "scp file.txt user@server:/tmp/",
    "cat myfile.txt",  // should this be a slot?
    "cat file123.txt", // should this be a slot?
    "cp file.txt backup.txt",
    "git add file.txt",
    "rm -f file.txt",
    "vim file.txt",
];

commands.forEach((cmd, idx) => {
    const result = extractCommandTemplate(cmd);
    console.log(`[${idx}] "${cmd}" -> "${result}"`);
});

console.log("\n=== Testing ShellMarkov with slot detection ===");

// Train a small model with corpus commands that have placeholders
const corpus = [
    "ls",
    "cat file.txt",
    "cat file.log",
    "grep error file.txt",
    "cp file.txt backup.txt",
    "scp file.txt user@server:/tmp/",
    "git add file.txt",
    "rm -f file.txt",
    "vim file.txt",
    "curl https://example.com",
    "ssh user@server",
    "cd /home/user",
];

const model = new ShellMarkov(4, 0.05).train(corpus);

// Test _findBestMatchingTemplate
console.log("\n--- Testing _findBestMatchingTemplate ---\n");

const testCandidates = [
    "cat mydata.txt",
    "cat very_long_filename_with_many_chars.log",
    "grep warning /var/log/syslog",
    "cp important.docx backup_2026.docx",
    "scp myfile.tar.gz root@192.168.1.100:/root/",
    "git add src/main.js",
    "rm -rf node_modules",
    "nano config.json",
    "curl http://localhost:3000/api/data",
    "ssh admin@10.0.0.1",
    "cd /tmp/test",
];

testCandidates.forEach((cand, idx) => {
    const template = model._findBestMatchingTemplate(cand);
    console.log(`[${idx}] Candidate: "${cand}"`);
    console.log(`      Best template: ${template ? `"${template.template}"` : "null"}`);
    console.log(`      Has slots: ${template ? template.hasSlots : "N/A"}`);
    console.log();
});

console.log("\n=== Testing commandLogP for slot-aware matching ===");

const testCommands = [
    { cmd: "cat mydata.txt", expectedHasSlots: true },
    { cmd: "cat very_long_filename.log", expectedHasSlots: true },
    { cmd: "ls", expectedHasSlots: false },
    { cmd: "git status", expectedHasSlots: false },
    { cmd: "scp file.txt user@server:/tmp/", expectedHasSlots: true },
    { cmd: "ssh admin@192.168.1.1", expectedHasSlots: true },
];

testCommands.forEach((tc, idx) => {
    const logP = model.commandLogP(tc.cmd);
    const template = model._findBestMatchingTemplate(tc.cmd);
    console.log(`[${idx}] Command: "${tc.cmd}"`);
    console.log(`      logP: ${logP.toFixed(4)}`);
    console.log(`      Template: ${template ? `"${template.template}"` : "null"}`);
    console.log(`      Has slots: ${template ? template.hasSlots : "N/A"}`);
    console.log(`      Expected has slots: ${tc.expectedHasSlots}`);
    console.log();
});

console.log("\n=== Testing compareToTemplate and fixedLength calculation ===");
const { compareToTemplate } = require("./src/ui/decoders/ssh-keystrokes/markov");

const compareTestCases = [
    { candidate: "cat mydata.txt", corpus: "cat file.txt" },
    { candidate: "cat file.txt", corpus: "cat file.txt" },
    { candidate: "cp important.docx backup_2026.docx", corpus: "cp file.txt backup.txt" },
    { candidate: "scp myfile.tar.gz root@192.168.1.100:/root/", corpus: "scp file.txt user@server:/tmp/" },
];

compareTestCases.forEach((tc, idx) => {
    const result = compareToTemplate(tc.candidate, tc.corpus);
    console.log(`[${idx}] Candidate: "${tc.candidate}"`);
    console.log(`      Corpus: "${tc.corpus}"`);
    console.log(`      Skeleton match: ${result.skeletonMatch}`);
    console.log(`      Has slots: ${result.hasSlots}`);
    console.log(`      Corpus length: ${result.corpusLength}`);
    console.log(`      Fixed length: ${result.fixedLength}`);
    console.log(`      Candidate length: ${result.candidateLength}`);
    console.log();
});

console.log("\n=== Testing detectSlotsInCommand ===");
const { detectSlotsInCommand } = require("./src/ui/decoders/ssh-keystrokes/markov");

const detectTestCases = [
    "cat file.txt",
    "cp file.txt backup.txt",
    "scp file.txt user@server:/tmp/",
    "curl https://example.com/api/v1/data",
    "grep -r error /var/log/",
    "vim ~/.ssh/id_rsa",
    "git add src/main.js src/utils.js",
    "nano config.json",
    "touch test.txt",
    "rm -rf node_modules",
    "mv oldname newname",
];

detectTestCases.forEach((cmd, idx) => {
    const slots = detectSlotsInCommand(cmd);
    console.log(`[${idx}] Command: "${cmd}"`);
    console.log(`      Slots detected: ${slots.length}`);
    slots.forEach((slot, sIdx) => {
        console.log(`        [${sIdx}] type: "${slot.type}", match: "${slot.match}", start: ${slot.start}, end: ${slot.end}`);
    });
    console.log();
});
