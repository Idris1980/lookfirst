// The parts of the AI feature that do not need VS Code: what is asked, how
// the answer is read, and how it is shown. Kept apart so they can be tested
// with plain Node.

const FENCE = '```';

// languageName turns a VS Code display language such as "sv" or "en-us"
// into a name the model understands, such as "Swedish".
function languageName(code) {
  try {
    const name = new Intl.DisplayNames(['en'], { type: 'language' }).of(code);
    if (name && name.toLowerCase() !== code.toLowerCase()) return name;
  } catch {
    // unknown code: fall through
  }
  return 'English';
}

// buildPrompt writes the request. Everything in it is shown to the user,
// exactly as it will be sent, before anything is sent.
function buildPrompt({ title, detail, fileName, languageId, excerpt, start, end, line, answerLanguage }) {
  return [
    'You are helping a developer understand a security risk that LookFirst, a tool that reads code without running it, found in their code, and fix it.',
    '',
    `Finding: ${title}`,
    `Why it matters: ${detail}`,
    `File: ${fileName} (${languageId})`,
    `The excerpt below is lines ${start}-${end} of the file. The finding is on line ${line} of the file, which is line ${line - start + 1} of the excerpt.`,
    'Passwords and keys have been replaced with placeholders such as «SECRET_1». Prefer a fix that does not need the secret in the code at all, such as an environment variable, a key vault or a parameter. If a placeholder must stay, keep it exactly as it is.',
    '',
    FENCE + (languageId || ''),
    excerpt,
    FENCE,
    '',
    `Answer in ${answerLanguage}, in exactly this format:`,
    '',
    'EXPLANATION:',
    '(3 to 6 short sentences in plain language for someone who is not a security expert: what the problem is, what could happen, and what your fix changes)',
    '',
    'FIXED CODE:',
    FENCE + (languageId || ''),
    '(the whole excerpt again with the fix applied, and nothing else changed)',
    FENCE,
    '',
    'If the finding is a false alarm, say so in the explanation and repeat the excerpt unchanged.',
  ].join('\n');
}

// parseAnswer reads the model's reply. code is null when the reply has no
// fixed code we can trust to put back into the file.
function parseAnswer(text) {
  const reply = String(text || '');
  const fixedAt = reply.search(/FIXED CODE:/i);
  const explAt = reply.search(/EXPLANATION:/i);
  let explanation;
  if (explAt >= 0) {
    explanation = reply.slice(explAt + 'EXPLANATION:'.length, fixedAt > explAt ? fixedAt : undefined);
  } else {
    explanation = fixedAt >= 0 ? reply.slice(0, fixedAt) : reply;
  }
  explanation = explanation.replace(new RegExp(FENCE + '[\\s\\S]*?' + FENCE, 'g'), '').trim();

  let code = null;
  if (fixedAt >= 0) {
    const m = reply.slice(fixedAt).match(/```[^\n]*\n([\s\S]*?)\n?```/);
    if (m) code = m[1];
  }
  return { explanation, code };
}

// restoreSecrets puts the real values back into a suggested fix. This only
// happens on the user's machine, after the answer has come back.
function restoreSecrets(code, secrets) {
  let out = code;
  for (const [token, value] of Object.entries(secrets || {})) {
    out = out.split(token).join(value);
  }
  return out;
}

function escapeHTML(s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&#34;').replace(/'/g, '&#39;');
}

// answerHTML shows the reply. The model's text is untrusted: it is escaped
// and shown as plain text, and the page runs no scripts. The only links are
// the two commands passed in, which VS Code allows for this panel alone.
function answerHTML({ title, fileName, modelName, explanation, code, showHref, applyHref }) {
  const paragraphs = explanation.split(/\n\s*\n/).map((p) => `<p>${escapeHTML(p.trim())}</p>`).join('\n');
  const actions = code === null
    ? '<p class="note">The answer did not include fixed code in the expected form, so there is nothing to apply.</p>'
    : `<p class="actions"><a class="button" href="${escapeHTML(showHref)}" title="Compare your code with the suggested fix, side by side">Show the change</a>
       <a class="button secondary" href="${escapeHTML(applyHref)}" title="Put the suggested fix into ${escapeHTML(fileName)}. You are asked first, and Ctrl+Z undoes it">Apply to ${escapeHTML(fileName)}</a></p>
       <p class="note">Nothing changes in your file until you choose Apply, and you can undo it afterwards. Read the change first: the suggestion comes from an AI model and can be wrong.</p>
       <h2>Suggested code</h2><pre>${escapeHTML(code)}</pre>`;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>LookFirst AI</title>
<style>
body { font: 14px/1.55 var(--vscode-font-family, system-ui, sans-serif); color: var(--vscode-foreground); padding: 8px 20px 32px; max-width: 900px; }
h1 { font-size: 18px; margin: 12px 0 4px; } h2 { font-size: 14px; margin: 24px 0 8px; }
.meta { color: var(--vscode-descriptionForeground); font-size: 12px; margin: 0 0 16px; }
pre { background: var(--vscode-textCodeBlock-background); padding: 12px; border-radius: 6px; overflow-x: auto; font: 12.5px/1.5 var(--vscode-editor-font-family, monospace); white-space: pre; }
.actions { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 20px; }
.button { background: var(--vscode-button-background); color: var(--vscode-button-foreground); padding: 6px 14px; border-radius: 4px; text-decoration: none; }
.button.secondary { background: var(--vscode-button-secondaryBackground); color: var(--vscode-button-secondaryForeground); }
.note { color: var(--vscode-descriptionForeground); font-size: 12.5px; }
</style></head>
<body>
<h1>${escapeHTML(title)}</h1>
<p class="meta">${escapeHTML(fileName)} · answered by ${escapeHTML(modelName)} · AI answers can be wrong</p>
${paragraphs}
${actions}
</body></html>`;
}

// pickModel chooses which language model to ask. A name in the setting
// wins when a model's name, family or id contains it. Otherwise the largest
// model wins, and small ones ("mini", "nano", "flash") only if nothing else
// is there: a careful explanation matters more than a fast one.
function pickModel(models, wanted) {
  const want = String(wanted || '').trim().toLowerCase();
  if (want) {
    const match = models.find((m) => [m.name, m.family, m.id].some((s) => String(s || '').toLowerCase().includes(want)));
    if (match) return match;
  }
  const small = (m) => /mini|nano|flash|haiku|small/i.test(`${m.family} ${m.name} ${m.id}`);
  return [...models].sort((a, b) => (small(a) - small(b)) || ((b.maxInputTokens || 0) - (a.maxInputTokens || 0)))[0];
}

// replaceLines returns text with lines start..end (counting from 1, both
// included) replaced by code, keeping the file's own line endings.
function replaceLines(text, start, end, code) {
  const eol = text.includes('\r\n') ? '\r\n' : '\n';
  const lines = text.split(/\r?\n/);
  const fixed = code.split(/\r?\n/);
  lines.splice(start - 1, end - start + 1, ...fixed);
  return lines.join(eol);
}

module.exports = { languageName, buildPrompt, parseAnswer, restoreSecrets, escapeHTML, answerHTML, pickModel, replaceLines };
