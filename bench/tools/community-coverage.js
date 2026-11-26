#!/usr/bin/env node
'use strict';

const { loadCorpus } = require('../lib/corpus');
const { summarizeCommunityCoverage } = require('../lib/community-contribution');

process.stdout.write(`${JSON.stringify(summarizeCommunityCoverage(loadCorpus()), null, 2)}\n`);
