'use strict';

const assert = require('assert');
const crypto = require('crypto');
const { createScoringEngine } = require('./index');

function solve(challenge) {
  for (let nonce = 0; ; nonce++) {
    const hash = crypto.createHash('sha256')
      .update(`${challenge.prefix}:${nonce}`)
      .digest('hex');
    if (hash.startsWith('0'.repeat(challenge.difficulty))) {
      return { challengeId: challenge.id, nonce, hash };
    }
  }
}

// Human-shaped, because index.js now scores with the same engine as server.js
// (see engine.js). The previous stub — two behavioural fields and nothing else
// — reads as zero input events to the shared detectors and correctly scores
// 0.6, which would make these assertions about the PoW gate fail for a reason
// that has nothing to do with the PoW gate.
const cleanSignals = {
  behavioral: {
    totalPoints: 60,
    trajectoryLength: 400,
    microTremorScore: 0.5,
    velocityVariance: 0.5,
    approachPoints: 12,
    approachDirectness: 0.4,
    explorationRatio: 0.35,
    overshootCorrections: 2,
    interactionDuration: 4200,
    touchEvents: 0,
    keyEvents: 0
  },
  environmental: { automationFlags: {} }
};
const cleanHeaders = {
  accept: 'text/html',
  'accept-language': 'en-US,en;q=0.9',
  'accept-encoding': 'gzip, deflate, br',
  connection: 'keep-alive'
};

{
  const engine = createScoringEngine({ secret: 'test-secret' });
  const result = engine.verify({}, '203.0.113.1', 'site', '', {}, null);
  assert.strictEqual(result.success, false, 'missing PoW must not succeed');
  assert.strictEqual(result.token, null, 'missing PoW must not mint a token');
  assert.strictEqual(result.reason, 'pow_not_satisfied');
}

{
  const engine = createScoringEngine({ secret: 'test-secret' });
  const result = engine.verify(cleanSignals, '203.0.113.1', 'site', 'Mozilla/5.0', cleanHeaders, {
    challengeId: 'not-issued', nonce: 0, hash: '0'.repeat(64)
  });
  assert.strictEqual(result.success, false, 'invalid PoW must not succeed');
  assert.strictEqual(result.token, null, 'invalid PoW must not mint a token');
}

{
  const engine = createScoringEngine({ secret: 'test-secret' });
  const challenge = engine.generateChallenge('site', '203.0.113.1', {
    difficulty: 1,
    scaleByReputation: false
  });
  // This unit test exercises the hard gate, not the elapsed-time heuristic.
  challenge.timestamp -= 2000;
  engine.powStore.challenges.get(challenge.id).timestamp -= 2000;
  const result = engine.verify(
    cleanSignals,
    '203.0.113.1',
    'site',
    'Mozilla/5.0',
    cleanHeaders,
    solve(challenge)
  );
  assert.strictEqual(result.success, true, 'valid PoW may succeed');
  assert.ok(result.token, 'valid PoW may mint a token');
}

{
  const engine = createScoringEngine({ secret: 'test-secret' });
  const challenge = engine.generateChallenge('site', '203.0.113.1', {
    difficulty: 1,
    scaleByReputation: false
  });
  const result = engine.verify(
    cleanSignals, '198.51.100.1', 'site', 'Mozilla/5.0', cleanHeaders, solve(challenge)
  );
  assert.strictEqual(result.success, false, 'a different network must not spend the challenge');
  assert.strictEqual(result.reason, 'pow_not_satisfied');
  assert.ok(result.detections.some((d) => d.reason.includes('challenge_network_mismatch')));
}

console.log('index.js security gate tests passed');
