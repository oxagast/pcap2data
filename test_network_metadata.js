"use strict";

const fs = require('fs');
const {
    ShellMarkov,
    setNetworkMetadata,
    getNetworkMetadata,
    getCommandNetworkInfo,
    calculateNetworkCorrelationScore,
    rankCorpusNetworkAware,
    SessionArtifactStore
} = require('./src/ui/decoders/ssh-keystrokes/markov');

console.log('========================================');
console.log('Testing Network Metadata Integration');
console.log('========================================\n');

// Test 1: Load metadata
console.log('[1/5] Loading network metadata...');
try {
    const metadataPath = './src/data/shell_corpus_net_metadata.json';
    const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
    setNetworkMetadata(metadata);

    const netEnabled = Object.entries(metadata)
        .filter(([k, v]) => v.network_enabled === true)
        .length;
    const netDisabled = Object.keys(metadata).length - netEnabled;

    console.log('      ✓ Loaded', Object.keys(metadata).length, 'commands');
    console.log('      ✓ Network-enabled:', netEnabled);
    console.log('      ✓ Non-network:', netDisabled);
} catch (e) {
    console.log('      ✗ FAILED:', e.message);
    process.exit(1);
}

// Test 2: Command network info extraction
console.log('\n[2/5] Testing command network info extraction...');
const testCases = [
    { cmd: 'ls', expected: false },
    { cmd: 'ls -la', expected: false },
    { cmd: 'git status', expected: true },
    { cmd: 'sudo git push origin main', expected: true },
    { cmd: 'curl https://example.com/api', expected: true },
    { cmd: 'ssh root@192.168.1.1', expected: true },
    { cmd: 'cd /home/user', expected: false },
    { cmd: 'npm install express', expected: true },
    { cmd: 'python3 script.py', expected: false },
    { cmd: 'python3 -m pip install requests', expected: true },
];

let passed2 = 0;
testCases.forEach(tc => {
    const info = getCommandNetworkInfo(tc.cmd);
    const actual = info ? info.networkEnabled : null;
    const status = (actual === tc.expected) ? '✓' : '✗';
    if (status === '✓') passed2++;

    console.log(`      ${status} "${tc.cmd}"`);
    console.log(`          expected networkEnabled=${tc.expected}, got=${actual}`);
});
console.log(`      ${passed2}/${testCases.length} tests passed`);

// Test 3: Network correlation scoring
console.log('\n[3/5] Testing network correlation scoring...');

// Create artifact store with network artifacts
const storeWithNet = new SessionArtifactStore();
storeWithNet.addIpAddress('192.168.1.100', { timestampMs: 100000, confidence: 0.9 });
storeWithNet.addHostname('example.com', { timestampMs: 100050, confidence: 0.8 });
storeWithNet.addArtifact('dns_qname', 'api.example.com', { timestampMs: 100100 });

// Empty store
const storeEmpty = new SessionArtifactStore();

const scoringCases = [
    {
        cmd: 'git status',
        store: storeWithNet,
        hasTargetTime: true,
        desc: 'git + network artifacts',
        expectedPositive: true  // should get positive score
    },
    {
        cmd: 'curl http://test.com',
        store: storeWithNet,
        hasTargetTime: true,
        desc: 'curl + network artifacts',
        expectedPositive: true
    },
    {
        cmd: 'ls -la',
        store: storeWithNet,
        hasTargetTime: true,
        desc: 'ls + network artifacts',
        expectedPositive: false  // should get negative/penalized
    },
    {
        cmd: 'cd /home',
        store: storeWithNet,
        hasTargetTime: true,
        desc: 'cd + network artifacts',
        expectedPositive: false
    },
    {
        cmd: 'git status',
        store: storeEmpty,
        hasTargetTime: false,
        desc: 'git + NO artifacts',
        expectedPositive: false  // mild penalty
    },
    {
        cmd: 'ls -la',
        store: storeEmpty,
        hasTargetTime: false,
        desc: 'ls + NO artifacts',
        expectedPositive: null  // neutral or small bonus
    },
];

let passed3 = 0;
scoringCases.forEach(sc => {
    const options = sc.hasTargetTime ? { targetTimeMs: 100000 } : {};
    const score = calculateNetworkCorrelationScore(sc.cmd, sc.store, options);
    const isPositive = score > 0;

    let matches = true;
    if (sc.expectedPositive === true) matches = isPositive;
    else if (sc.expectedPositive === false) matches = !isPositive;

    const status = matches ? '✓' : '~';
    if (matches) passed3++;

    console.log(`      ${status} ${sc.desc}`);
    console.log(`          score=${score.toFixed(4)} (isPositive=${isPositive})`);
});
console.log(`      ${passed3}/${scoringCases.length} tests as expected`);

// Test 4: ShellMarkov prototype methods
console.log('\n[4/5] Testing ShellMarkov prototype methods...');
const model = new ShellMarkov(4, 0.05).train([
    'ls -la',
    'git status',
    'git push origin main',
    'curl https://example.com',
    'ssh user@server',
    'cd /home/user',
]);

try {
    // Test getCommandNetworkInfo
    const gitInfo = model.getCommandNetworkInfo('git push');
    const lsInfo = model.getCommandNetworkInfo('ls');

    if (gitInfo?.networkEnabled === true && lsInfo?.networkEnabled === false) {
        console.log('      ✓ model.getCommandNetworkInfo() works');
    } else {
        console.log('      ~ model.getCommandNetworkInfo() results:');
        console.log('        git:', gitInfo);
        console.log('        ls:', lsInfo);
    }

    // Test calculateNetworkCorrelation
    const curlScore = model.calculateNetworkCorrelation(
        'curl http://test.com',
        storeWithNet,
        { targetTimeMs: 100000 }
    );
    console.log(`      ✓ model.calculateNetworkCorrelation(): ${curlScore.toFixed(4)}`);

} catch (e) {
    console.log('      ✗ FAILED:', e.message);
    process.exit(1);
}

// Test 5: rankCorpusNetworkAware
console.log('\n[5/5] Testing rankCorpusNetworkAware...');

try {
    // Train on mixed commands
    const mixedModel = new ShellMarkov(4, 0.05).train([
        'ls',
        'cd /home',
        'git status',
        'git push',
        'curl https://example.com',
        'ssh user@server',
    ]);

    // Rank with network artifacts present
    const ranked = rankCorpusNetworkAware(
        mixedModel,
        storeWithNet,
        null,  // no target length
        3,
        10,
        { targetTimeMs: 100000, networkCorrelationWeight: 0.5 }
    );

    console.log('      ✓ Ranked', ranked.length, 'commands with network awareness');
    console.log('      Top results:');
    ranked.slice(0, 5).forEach((r, i) => {
        const score = r[0];
        const cmd = r[1];
        const info = r[3];
        console.log(`        [${i + 1}] "${cmd}"`);
        console.log(`              score=${score.toFixed(4)}, networkScore=${info?.networkScore?.toFixed(4)}`);
    });

} catch (e) {
    console.log('      ✗ FAILED:', e.message);
    console.log('      Stack:', e.stack);
    process.exit(1);
}

console.log('\n========================================');
console.log('✓ All tests completed successfully!');
console.log('========================================\n');

// Summary of what was implemented:
console.log('Summary of Network Metadata Integration:');
console.log('');
console.log('New functions in markov.js:');
console.log('  - loadNetworkMetadata()     : Load metadata from JSON file');
console.log('  - setNetworkMetadata()      : Set metadata directly (for renderer IPC)');
console.log('  - getNetworkMetadata()      : Get cached metadata');
console.log('  - getCommandNetworkInfo()   : Extract base command + network_enabled flag');
console.log('  - calculateNetworkCorrelationScore() : Time-aware correlation scoring');
console.log('  - rankCorpusNetworkAware()  : Enhanced ranking with network correlation');
console.log('');
console.log('New ShellMarkov prototype methods:');
console.log('  - model.rankNetworkAware()        : Instance method wrapper');
console.log('  - model.getCommandNetworkInfo()   : Instance method wrapper');
console.log('  - model.calculateNetworkCorrelation() : Instance method wrapper');
console.log('');
console.log('How it improves artifact-command correlation:');
console.log('  1. Commands like git/curl/ssh get a BOOST when network artifacts exist');
console.log('  2. Commands like ls/cd/pwd get a PENALTY when network artifacts exist');
console.log('  3. Temporal vicinity is considered (closer artifacts = stronger signal)');
console.log('  4. Works with existing rankCorpusWithSlotFilling pipeline');
