// Asks Claude through the Claude Code program (claude) that the user already
// has and is signed in to, so the request is covered by their own Claude
// subscription and no API key is needed.
//
// Claude Code is an agent that can read files and run commands, so it is
// started as a plain question-and-answer: no tools, no customizations (no
// hooks, CLAUDE.md, plugins or MCP servers), no saved session, and in an
// empty folder of its own, so nothing in the user's projects is read.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const SYSTEM = 'You review code for security problems. Answer exactly in the format the request asks for, with nothing before or after it.';
const TIMEOUT_MS = 180_000;

// find returns the claude program to run: the path in the setting, the one
// on PATH, or the one that comes with the Claude Code extension for VS Code.
function find(custom, extensionsDir) {
  if (custom) return fs.existsSync(custom) ? custom : undefined;
  const exe = process.platform === 'win32' ? 'claude.exe' : 'claude';
  for (const dir of String(process.env.PATH || '').split(path.delimiter)) {
    if (dir && fs.existsSync(path.join(dir, exe))) return path.join(dir, exe);
  }
  const local = path.join(os.homedir(), '.local', 'bin', exe);
  if (fs.existsSync(local)) return local;
  // The newest Claude Code extension that carries its own copy.
  try {
    const found = fs.readdirSync(extensionsDir)
      .filter((d) => d.startsWith('anthropic.claude-code-'))
      .sort((a, b) => b.localeCompare(a, undefined, { numeric: true }))
      .map((d) => path.join(extensionsDir, d, 'resources', 'native-binary', exe))
      .find((p) => fs.existsSync(p));
    if (found) return found;
  } catch { /* no extensions folder */ }
  return undefined;
}

// model turns the setting into what claude --model takes: an alias such as
// "opus" or "sonnet", or a full id. Empty leaves the choice to the plan.
function model(wanted) {
  const want = String(wanted || '').trim().toLowerCase();
  if (/^claude-[a-z0-9-]+$/.test(want)) return want;
  return ['opus', 'sonnet', 'haiku', 'fable'].find((m) => want.includes(m));
}

function args(modelName) {
  const a = [
    '-p', '--output-format', 'json',
    '--safe-mode', '--tools', '', '--strict-mcp-config', '--disable-slash-commands', '--no-session-persistence',
    '--system-prompt', SYSTEM,
  ];
  if (modelName) a.push('--model', modelName);
  return a;
}

// ask sends the prompt on standard input and returns { text, usage }.
// onCancel is given a function that stops the run.
function ask({ bin, modelName, prompt, onCancel }) {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'lookfirst-claude-'));
  const cleanup = () => fs.rm(cwd, { recursive: true, force: true }, () => {});
  return new Promise((resolve, reject) => {
    const child = cp.spawn(bin, args(modelName), { cwd, windowsHide: true, shell: false, stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    const timer = setTimeout(() => child.kill(), TIMEOUT_MS);
    if (onCancel) onCancel(() => child.kill());
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', (e) => {
      clearTimeout(timer);
      cleanup();
      reject(new Error(e.code === 'ENOENT' ? 'the Claude Code program was not found.' : e.message));
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      cleanup();
      if (signal) {
        reject(new Error('Claude Code was stopped before it answered.'));
        return;
      }
      let reply;
      try {
        reply = JSON.parse(out);
      } catch {
        reject(new Error(explain(err || out || `Claude Code ended with code ${code}.`)));
        return;
      }
      if (reply.is_error || code !== 0) {
        reject(new Error(explain(String(reply.result || err || `Claude Code ended with code ${code}.`))));
        return;
      }
      resolve({ text: String(reply.result || ''), usage: reply.usage || {} });
    });
    child.stdin.end(prompt);
  });
}

// explain turns Claude Code's own messages into advice.
function explain(message) {
  const m = String(message).trim();
  if (/log ?in|authenticat|credential|\/login/i.test(m)) {
    return 'Claude Code is not signed in. Open a terminal, run claude, and sign in with your Claude account, then try again.';
  }
  if (/usage limit|rate limit|limit reached/i.test(m)) {
    return 'your Claude plan has reached its usage limit for now. Try again later.';
  }
  return m.split('\n').slice(0, 3).join(' ');
}

// tokens sums what a reply used, for showing next to the answer.
function tokens(usage) {
  return ['input_tokens', 'output_tokens', 'cache_creation_input_tokens'].reduce((n, k) => n + (Number(usage[k]) || 0), 0);
}

module.exports = { find, model, args, ask, explain, tokens };
