'use strict';

/**
 * Submits corpus samples to a running server and collects the verdicts.
 *
 * ## Why every sample gets its own client IP
 *
 * The server escalates PoW difficulty per `pow:{siteKey}:{ip}` — 10 challenges
 * in a minute moves it to 5, 20 moves it to 6. A few hundred samples from one
 * address would therefore spend most of the run solving 16.7M-hash challenges,
 * and worse, the later samples would be scored under rate-limit detections the
 * earlier ones never saw. The measurement would drift as a function of position
 * in the corpus.
 *
 * So each sample presents a distinct address derived from its id. That is only
 * possible because loopback is in the default trusted-proxy set, so a request
 * from 127.0.0.1 may set `X-Forwarded-For` — the same v1.16.0 mechanism that
 * lets Railway's edge do it, used here deliberately.
 *
 * The address is part of the label, not a workaround: a hosted computer-use
 * agent really does arrive from a datacenter range, and a human on a home
 * connection really does not. Samples may set `clientIp` to say so; anything
 * that does not gets a documentation-range address (RFC 5737), which no
 * detection treats as anything in particular.
 */

const crypto = require('crypto');
const { buildVerifyBody } = require('./pow');

/** RFC 5737 TEST-NET-2 and TEST-NET-3: reserved, routable nowhere, in no CIDR list. */
const NEUTRAL_PREFIXES = ['198.51.100', '203.0.113'];

function neutralIpFor(id) {
  const digest = crypto.createHash('sha256').update(id).digest();
  const prefix = NEUTRAL_PREFIXES[digest[0] % NEUTRAL_PREFIXES.length];
  // .0 and .255 are the network and broadcast addresses; keep to 1-254.
  return `${prefix}.${(digest[1] % 254) + 1}`;
}

const DEFAULT_UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

/**
 * Runs one sample. Returns the verdict plus enough context for the reporter to
 * attribute a failure to a persona and a signal.
 */
async function replaySample(serverUrl, sample, opts = {}) {
  const siteKey = opts.siteKey || 'bench';
  const clientIp = sample.clientIp || neutralIpFor(sample.id);

  const headers = {
    'Content-Type': 'application/json',
    'User-Agent': DEFAULT_UA,
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    ...(sample.headers || {}),
    'X-Forwarded-For': clientIp,
  };

  try {
    const { body, difficulty } = await buildVerifyBody(
      serverUrl,
      siteKey,
      sample.signals,
      headers
    );

    const res = await fetch(`${serverUrl}/api/verify`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`verify returned ${res.status}`);
    const verdict = await res.json();

    return {
      sample,
      clientIp,
      difficulty,
      score: verdict.score,
      recommendation: verdict.recommendation,
      detections: verdict.detections || [],
      categoryScores: verdict.categoryScores || {},
    };
  } catch (err) {
    return { sample, clientIp, error: err.message };
  }
}

/**
 * Replays the corpus with bounded concurrency.
 *
 * Concurrency is capped because the thing being measured is a scorer, not a
 * load balancer: enough parallelism to keep the run short, not so much that
 * requests queue and the PoW timing the server scores reflects our own backlog
 * rather than the solve.
 */
async function replayCorpus(serverUrl, samples, opts = {}) {
  const concurrency = opts.concurrency || 4;
  const results = new Array(samples.length);
  let next = 0;
  let done = 0;

  const worker = async () => {
    for (;;) {
      const i = next++;
      if (i >= samples.length) return;
      results[i] = await replaySample(serverUrl, samples[i], opts);
      done++;
      if (opts.onProgress) opts.onProgress(done, samples.length);
    }
  };

  await Promise.all(Array.from({ length: concurrency }, worker));
  return results;
}

module.exports = { DEFAULT_UA, neutralIpFor, replayCorpus, replaySample };
