const test = require('node:test');
const assert = require('node:assert');
const cc = require('../claudecode');

test('Claude Code is started as a plain question and answer', () => {
  const a = cc.args(undefined);
  assert.ok(a.includes('-p') && a.includes('--safe-mode') && a.includes('--strict-mcp-config'));
  assert.strictEqual(a[a.indexOf('--tools') + 1], '', 'no tools');
  assert.ok(!a.includes('--model'), 'the plan chooses when no model is set');
  assert.deepStrictEqual(cc.args('opus').slice(-2), ['--model', 'opus']);
});

test('model names become what claude --model takes', () => {
  assert.strictEqual(cc.model(''), undefined);
  assert.strictEqual(cc.model('Claude'), undefined);
  assert.strictEqual(cc.model('Sonnet'), 'sonnet');
  assert.strictEqual(cc.model('claude-opus-5-5'), 'claude-opus-5-5');
});

test('Claude Code messages become advice', () => {
  assert.match(cc.explain('Invalid API key · Please run /login'), /not signed in/);
  assert.match(cc.explain('Claude usage limit reached'), /usage limit/);
  assert.strictEqual(cc.tokens({ input_tokens: 10, output_tokens: 5, cache_read_input_tokens: 900 }), 15);
});
