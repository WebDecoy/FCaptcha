'use strict';

/**
 * A Node-side implementation of the client's proof-of-work handshake.
 *
 * Without this every bench sample is dominated by one detection — "No PoW
 * solution provided", score 0.9, confidence 0.95 — which would swamp the
 * signals we are actually trying to measure and make every persona look like a
 * bot. The bench has to complete the same handshake a browser does.
 *
 * Mirrors `client/fcaptcha.js`: the committed input is
 *
 *     sha256(`${prefix}:${signalsHash}:${nonce}`)
 *
 * and must begin with `difficulty` hex zeros, where `signalsHash` is
 * `sha256(JSON.stringify(signals))` over the exact bytes sent as `signalsJson`.
 * The server re-hashes `signalsJson` and compares, so the string is transmitted
 * rather than re-serialized server-side — key order would otherwise differ
 * across languages.
 */

const crypto = require('crypto');

const sha256 = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

/**
 * Difficulty grows 16× per level, so a bench that lets itself be escalated is a
 * bench that takes minutes instead of seconds. Callers give each sample its own
 * client IP to stay at the floor; this cap exists so a misconfigured run fails
 * loudly instead of appearing to hang.
 */
const MAX_DIFFICULTY = 5;

/**
 * ## Why the solver is deliberately slowed down
 *
 * Node's `crypto.createHash` runs well over a million short SHA-256s per
 * second. A browser worker using `crypto.subtle.digest` — one async call per
 * attempt — manages a small fraction of that. The server knows this and scores
 * it: a solve rate above ~1M/s is reported as "PoW completed impossibly fast",
 * and the un-spoofable server-side gap between issuing a challenge and
 * receiving its solution is flagged below 1.5s as "Challenge solved too fast".
 *
 * An unthrottled harness therefore trips both on every single sample, human and
 * agent alike, and the panel measures nothing but the harness. Pacing is not
 * cosmetic: `duration` stays true wall-clock, we simply make the harness take
 * as long as the thing it stands in for. Reporting a fabricated duration
 * instead would measure the fabrication.
 */
const TARGET_HASH_RATE = 200_000; // per second; mid-range of the server's 50k-500k window
// Cleared against the server's 1.5s floor, measured from when the challenge
// arrives rather than when it is requested — see buildVerifyBody. 100ms of
// margin is enough once the round trip is outside the measurement.
const MIN_CHALLENGE_AGE_MS = 1_600;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function fetchChallenge(serverUrl, siteKey, headers = {}) {
  const url = `${serverUrl}/api/pow/challenge?siteKey=${encodeURIComponent(siteKey)}`;
  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error(`challenge fetch failed: ${res.status}`);
  return res.json();
}

/**
 * Finds a nonce satisfying the challenge. Returns the solution plus real
 * wall-clock timing — the server scores how long the solve took (too fast means
 * a precomputed or offloaded solve, too slow means an external API in the
 * loop), so reporting honest numbers here matters. A fabricated `duration`
 * would be measuring the fabrication.
 */
async function solve(challenge, signalsHash, opts = {}) {
  if (challenge.difficulty > MAX_DIFFICULTY) {
    throw new Error(
      `refusing to solve difficulty ${challenge.difficulty}: the bench has been ` +
        'rate-escalated. Give each sample a distinct client IP (see replay.js).'
    );
  }

  const hashRate = opts.hashRate || TARGET_HASH_RATE;
  const target = '0'.repeat(challenge.difficulty);
  const prefix = `${challenge.prefix}:${signalsHash}`;
  const started = process.hrtime.bigint();
  const batch = 2048;

  let nonce = 0;
  let hash = sha256(`${prefix}:${nonce}`);
  while (!hash.startsWith(target)) {
    nonce++;
    hash = sha256(`${prefix}:${nonce}`);

    // Yield and pace once per batch. Sleeping to the schedule rather than after
    // the fact keeps `duration` an honest measurement of elapsed time.
    if (nonce % batch === 0) {
      const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
      const owedMs = (nonce / hashRate) * 1000 - elapsedMs;
      if (owedMs > 0) await sleep(owedMs);
    }
  }

  // Settle up for the final partial batch.
  //
  // Difficulty-4 solve lengths are geometric with a mean of 65536, so roughly 3%
  // of solves finish inside the first batch and never reach the pacing check at
  // all. Those came back at raw Node speed and the server flagged them "PoW
  // completed impossibly fast" — 4 of 99 human samples in CI, which is precisely
  // the tail probability. A per-batch check alone leaves that tail unpaced.
  // The settle has to be precise, not merely present. A short solve owes only a
  // few milliseconds, and setTimeout cannot deliver those — under concurrency it
  // routinely overshoots by tens of milliseconds, which for a small `nonce` drags
  // the implied rate below the server's slow bound and earns the opposite
  // complaint, "PoW timing suggests external processing". That is how the harness
  // managed to trip both ends of the same check.
  //
  // So: sleep for the bulk, then spin for the remainder. Spinning is wasteful by
  // design and bounded to a few milliseconds; the alternative is a duration that
  // misreports how long the work took.
  const owedMs = () => (nonce / hashRate) * 1000 - Number(process.hrtime.bigint() - started) / 1e6;
  const SPIN_THRESHOLD_MS = 6;
  const owed = owedMs();
  if (owed > SPIN_THRESHOLD_MS) await sleep(owed - SPIN_THRESHOLD_MS);
  while (owedMs() > 0) { /* spin to land on the target rate */ }

  const duration = Number(process.hrtime.bigint() - started) / 1e6;
  return {
    challengeId: challenge.challengeId,
    nonce,
    hash,
    iterations: nonce + 1,
    duration,
    difficulty: challenge.difficulty,
    signalsHash,
  };
}

/**
 * Builds the full `/api/verify` body for a set of signals: fetches a challenge,
 * stamps its nonce into `signals.meta` (the server checks the echo), commits the
 * signals into the PoW input, and solves.
 */
async function buildVerifyBody(serverUrl, siteKey, signals, headers = {}, opts = {}) {
  const challenge = await fetchChallenge(serverUrl, siteKey, headers);

  // Start the clock when the challenge *arrives*, not when we ask for it.
  //
  // The server measures from the moment it created the challenge, which is after
  // our request reached it. Timing the wait from before the fetch therefore
  // spends part of the budget on the round trip: with a 1600ms target against a
  // 1500ms server floor, a challenge fetch slower than 100ms leaves the server
  // measuring under its floor and every sample trips "Challenge solved too
  // fast". That is comfortably reachable on a loaded CI runner, and it failed
  // the gate on main.
  //
  // Measuring from arrival makes the wait strictly longer than what the server
  // sees as elapsed, so the margin no longer depends on network latency.
  const receivedAt = Date.now();

  const committed = {
    ...signals,
    meta: { ...(signals.meta || {}), challengeNonce: challenge.nonce },
  };

  const signalsJson = JSON.stringify(committed);
  const signalsHash = sha256(signalsJson);
  const solution = await solve(challenge, signalsHash, opts);

  // The server measures the gap between issuing the challenge and receiving the
  // solution, which no client can forge. A real page spends this time rendering
  // and waiting for someone to interact; the harness has to spend it too.
  const minAge = opts.minChallengeAgeMs ?? MIN_CHALLENGE_AGE_MS;
  const remaining = minAge - (Date.now() - receivedAt);
  if (remaining > 0) await sleep(remaining);

  return {
    body: {
      siteKey,
      signals: committed,
      signalsJson,
      powSolution: {
        challengeId: solution.challengeId,
        nonce: solution.nonce,
        hash: solution.hash,
        signalsHash,
      },
      powTiming: {
        duration: solution.duration,
        iterations: solution.iterations,
        difficulty: solution.difficulty,
      },
    },
    difficulty: solution.difficulty,
  };
}

module.exports = {
  MAX_DIFFICULTY,
  MIN_CHALLENGE_AGE_MS,
  TARGET_HASH_RATE,
  buildVerifyBody,
  fetchChallenge,
  sha256,
  solve,
};
