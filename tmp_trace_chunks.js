// Does buildSshKeystrokeExportJson produce markovChunks in the JSON?
const path = require("path");
const fs = require("fs");
const {
    ShellMarkov,
    cleanLines,
} = require(path.join("/home/marshall/Hacks/projects/packetsnitch/src/ui/decoders/ssh-keystrokes/markov"));
const {
    buildSshKeystrokeExportJson,
} = require(path.join(
    "/home/marshall/Hacks/projects/packetsnitch/src/ui/decoders/ssh-keystrokes/export"
));

// Mimic a multi-command keystroke session.
const delays = [];
// ls (2 keys then 700ms return)
delays.push({ delay: 30, index: 1, packetLength: 50 });
delays.push({ delay: 35, index: 2, packetLength: 50 });
delays.push({ delay: 700, index: 3, packetLength: 80 });
// cat foo.txt (10 keys then 900ms return)
delays.push({ delay: 40, index: 4, packetLength: 50 });
delays.push({ delay: 60, index: 5, packetLength: 50 });
delays.push({ delay: 65, index: 6, packetLength: 50 });
delays.push({ delay: 32, index: 7, packetLength: 50 });
delays.push({ delay: 38, index: 8, packetLength: 50 });
delays.push({ delay: 42, index: 9, packetLength: 50 });
delays.push({ delay: 66, index: 10, packetLength: 50 });
delays.push({ delay: 34, index: 11, packetLength: 50 });
delays.push({ delay: 71, index: 12, packetLength: 50 });
delays.push({ delay: 900, index: 13, packetLength: 80 });

// Train Markov model
const corpus = fs.readFileSync("/home/marshall/Hacks/projects/packetsnitch/src/data/shell_corpus_sorted.txt", "utf8");
const model = new ShellMarkov(4, 0.05).train(cleanLines(corpus));
console.log("model trained:", model.nCommands, "commands");

// Whole-session markov
const beam = model.generateBeam(7, 3, 300, 30, 30);
const reranked = model.rank(beam.map(([, t]) => t), delays.map(d => d.delay), 0.22).slice(0, 5);
console.log("Whole-session markovCandidates top-5:", JSON.stringify(reranked, null, 2));

// Build the cached shape the analyzer actually passes in:
const cached = {
    flow: { srcIp: "10.0.2.3", srcPort: 22, dstIp: "10.0.2.20", dstPort: 22, packets: [], firstTimestamp: 0, lastTimestamp: 2000 },
    delays,
    delaysWithIdx: delays,
    estimatedCommandLength: 10,
    markovCandidates: reranked,
    markovChunks: [
        {
            keystrokeCount: 3,
            startIdx: 0,
            endIdx: 2,
            top: [
                { score: -1.0, text: "ls -la" },
                { score: -2.0, text: "ls -l" },
            ],
        },
        {
            keystrokeCount: 10,
            startIdx: 3,
            endIdx: 12,
            top: [
                { score: -1.2, text: "cat foo.txt" },
                { score: -1.5, text: "cat bar.txt" },
            ],
        },
    ],
};

const j = buildSshKeystrokeExportJson(cached);
console.log("\n--- JSON KEYS ---");
console.log(Object.keys(j));
console.log("\n--- markovTopGuess ---");
console.log(JSON.stringify(j.markovTopGuess, null, 2));
console.log("\n--- markovChunks ---");
console.log(JSON.stringify(j.markovChunks, null, 2));
console.log("\n--- markovTargetLength ---");
console.log(j.markovTargetLength);
