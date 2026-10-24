const test = require('node:test');
const assert = require('node:assert');
const ai = require('../ai');

test('languageName', () => {
  assert.strictEqual(ai.languageName('sv'), 'Swedish');
  assert.strictEqual(ai.languageName('en-us'), 'American English');
  assert.strictEqual(ai.languageName('not-a-language-zz'), 'English');
});

test('buildPrompt tells the model where the finding is and keeps placeholders', () => {
  const p = ai.buildPrompt({
    title: 'Password or key written in the code', detail: 'admin_password is in the file.',
    fileName: 'main.tf', languageId: 'terraform', excerpt: 'admin_password = "«SECRET_1»"',
    start: 80, end: 95, line: 88, answerLanguage: 'Swedish',
  });
  assert.match(p, /line 88 of the file, which is line 9 of the excerpt/);
  assert.match(p, /«SECRET_1»/);
  assert.match(p, /Answer in Swedish/);
});

test('parseAnswer reads explanation and code', () => {
  const r = ai.parseAnswer('EXPLANATION:\nThe password is in the file.\n\nFIXED CODE:\n```terraform\nadmin_password = var.admin_password\n```\n');
  assert.strictEqual(r.explanation, 'The password is in the file.');
  assert.strictEqual(r.code, 'admin_password = var.admin_password');
});

test('parseAnswer without code gives null, so nothing can be applied', () => {
  const r = ai.parseAnswer('I am not sure what to do here.');
  assert.strictEqual(r.code, null);
  assert.strictEqual(r.explanation, 'I am not sure what to do here.');
});

test('restoreSecrets puts every original back', () => {
  assert.strictEqual(ai.restoreSecrets('a=«SECRET_1» b=«SECRET_1» c=«SECRET_2»', { '«SECRET_1»': 'x', '«SECRET_2»': 'y' }), 'a=x b=x c=y');
});

test('answerHTML escapes everything the model writes', () => {
  const html = ai.answerHTML({
    title: 'T', fileName: 'f.js', modelName: '<b>m</b>',
    explanation: '<script>alert(1)</script> <img src=x onerror=alert(1)>',
    code: '</pre><script>x()</script>',
    showHref: 'command:lookFirst.showFix?%5B1%5D', applyHref: 'command:lookFirst.applyFix?%5B1%5D',
  });
  assert.ok(!/<script/i.test(html), 'contains a script tag');
  assert.ok(!/<img/i.test(html), 'contains an img tag');
  assert.ok(!/<b>m<\/b>/.test(html), 'model name not escaped');
  assert.match(html, /default-src 'none'/);
});

test('replaceLines keeps the line endings of the file', () => {
  assert.strictEqual(ai.replaceLines('a\r\nb\r\nc\r\nd', 2, 3, 'X\nY\nZ'), 'a\r\nX\r\nY\r\nZ\r\nd');
  assert.strictEqual(ai.replaceLines('a\nb\nc', 1, 1, 'A'), 'A\nb\nc');
});

test('pickModel prefers a large model, and the setting wins', () => {
  const models = [
    { id: 'gpt-4o-mini', family: 'gpt-4o-mini', name: 'GPT-4o mini', maxInputTokens: 128000 },
    { id: 'gpt-4.1', family: 'gpt-4.1', name: 'GPT-4.1', maxInputTokens: 128000 },
    { id: 'claude-sonnet', family: 'claude-sonnet', name: 'Claude Sonnet', maxInputTokens: 200000 },
  ];
  assert.strictEqual(ai.pickModel(models, '').name, 'Claude Sonnet');
  assert.strictEqual(ai.pickModel(models, 'gpt-4.1').name, 'GPT-4.1');
  assert.strictEqual(ai.pickModel(models, 'no-such-model').name, 'Claude Sonnet');
  assert.strictEqual(ai.pickModel([models[0]], '').name, 'GPT-4o mini');
});
