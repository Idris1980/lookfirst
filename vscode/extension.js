// LookFirst shows what code would build or do, by running the bundled
// lookfirst program on it. The program only reads files; this extension never
// runs the user's code. Nothing is sent anywhere, except by the opt-in AI
// feature in explain.js, which shows the user what it sends first.
const vscode = require('vscode');
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const explain = require('./explain');

const SUPPORTED_EXT = new Set([
  '.tf', '.bicep', '.json', '.yml', '.yaml', '.py', '.js', '.mjs', '.cjs', '.ts', '.mts', '.cts',
  '.jsx', '.tsx', '.sh', '.bash', '.zsh', '.ps1', '.psm1',
]);

// For untitled documents we pick a file name from the language.
const LANGUAGE_FILE = {
  terraform: 'main.tf', bicep: 'main.bicep', json: 'template.json', yaml: 'file.yaml',
  dockercompose: 'docker-compose.yml', python: 'script.py', javascript: 'script.js',
  typescript: 'script.ts', javascriptreact: 'script.jsx', typescriptreact: 'script.tsx',
  shellscript: 'script.sh', powershell: 'script.ps1', dockerfile: 'Dockerfile',
};

const SEVERITY = {
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
};

let diagnostics;
let status;
let scratch;
const pasteTimers = new Map();
const checked = new Set(); // URIs of documents LookFirst has checked
const openable = new Map(); // path key -> URI of a file a shown report may open

function activate(context) {
  diagnostics = vscode.languages.createDiagnosticCollection('lookfirst');
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  status.command = 'lookFirst.show';
  scratch = path.join(context.globalStorageUri.fsPath, 'scratch');
  fs.mkdirSync(scratch, { recursive: true });

  context.subscriptions.push(
    diagnostics,
    status,
    vscode.commands.registerCommand('lookFirst.show', (uri) => show(context, uri)),
    vscode.commands.registerCommand('lookFirst.reveal', reveal),
    vscode.commands.registerCommand('lookFirst.check', () => {
      const doc = vscode.window.activeTextEditor && vscode.window.activeTextEditor.document;
      if (doc) checkDocument(doc, { announce: true });
    }),
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (setting('checkOnSave') && supported(doc)) checkDocument(doc, { announce: false });
    }),
    vscode.workspace.onDidChangeTextDocument(onChange),
    vscode.workspace.onDidCloseTextDocument((doc) => {
      diagnostics.delete(doc.uri);
      checked.delete(doc.uri.toString());
      tried.delete(doc.uri.toString());
    }),
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      updateContext(editor);
      checkOnOpen(editor);
    }),
    // The shield always counts what is in the Problems panel right now.
    vscode.languages.onDidChangeDiagnostics(() => updateContext(vscode.window.activeTextEditor)),
  );
  updateContext(vscode.window.activeTextEditor);
  checkOnOpen(vscode.window.activeTextEditor);
  explain.register(context, { openable, key, scratchCopy, removeScratch, runLookFirst });
}

function deactivate() {
  for (const t of pasteTimers.values()) clearTimeout(t);
}

function setting(name) {
  return vscode.workspace.getConfiguration('lookFirst').get(name);
}

function supported(doc) {
  if (doc.uri.scheme !== 'file' && doc.uri.scheme !== 'untitled') return false;
  const base = path.basename(doc.fileName).toLowerCase();
  if (base === 'dockerfile' || base.startsWith('dockerfile.') || base.endsWith('.dockerfile')) return true;
  if (base.startsWith('requirements') && base.endsWith('.txt')) return true;
  if (SUPPORTED_EXT.has(path.extname(base))) return true;
  return doc.isUntitled && LANGUAGE_FILE[doc.languageId] !== undefined;
}

// updateContext runs when the active editor or the problems change. Moving
// to the picture or another panel leaves no text editor; keep the status
// for the file the user was in.
function updateContext(editor) {
  if (!editor) return;
  const ok = supported(editor.document);
  vscode.commands.executeCommand('setContext', 'lookFirst.supported', ok);
  if (ok && checked.has(editor.document.uri.toString())) showStatus(editor.document);
  else status.hide();
}

// checkOnOpen checks a file the first time it is shown, quietly, so the
// shield and the squiggles are there before anyone saves anything.
const tried = new Set(); // URIs already checked, or tried, since they were opened
function checkOnOpen(editor) {
  if (!editor || !setting('checkOnOpen')) return;
  const doc = editor.document;
  const id = doc.uri.toString();
  if (doc.isUntitled || !supported(doc) || tried.has(id)) return;
  tried.add(id);
  checkDocument(doc, { announce: false });
}

// A larger insertion in one go is a paste or an AI assistant writing code.
function onChange(e) {
  if (!setting('checkOnPaste') || !supported(e.document)) return;
  if (e.reason === vscode.TextDocumentChangeReason.Undo || e.reason === vscode.TextDocumentChangeReason.Redo) return;
  const min = setting('pasteMinLines');
  const big = e.contentChanges.some((c) => c.text.split('\n').length >= min);
  if (!big) return;
  const key = e.document.uri.toString();
  clearTimeout(pasteTimers.get(key));
  pasteTimers.set(key, setTimeout(() => {
    pasteTimers.delete(key);
    checkDocument(e.document, { announce: true, pasted: true });
  }, 1200));
}

// checkDocument reads the document as it is in the editor, saved or not, by
// copying its text to a private scratch file with the same name.
async function checkDocument(doc, { announce, pasted }) {
  let report;
  const copy = scratchCopy(doc);
  try {
    report = await runLookFirst(['read', '--format', 'json', copy]);
  } catch (err) {
    if (announce && !/not supported yet|found nothing/.test(String(err.message))) {
      vscode.window.showErrorMessage('LookFirst: ' + err.message);
    }
    return;
  } finally {
    removeScratch(copy);
  }

  const items = [];
  for (const f of report.findings) {
    const line = Math.max(0, Math.min((f.line || 1) - 1, doc.lineCount - 1));
    const range = doc.lineAt(line).range;
    const d = new vscode.Diagnostic(range, `${f.title}: ${f.detail}`, SEVERITY[f.severity]);
    d.source = 'LookFirst';
    items.push(d);
  }
  checked.add(doc.uri.toString());
  diagnostics.set(doc.uri, items); // the shield follows through onDidChangeDiagnostics

  if (!announce) return;
  const serious = report.findings.filter((f) => f.severity === 'high');
  if (serious.length === 0) {
    if (!pasted) vscode.window.showInformationMessage('LookFirst: ' + report.summary.join(' '));
    return;
  }
  const titles = [...new Set(serious.map((f) => f.title))];
  const more = titles.length > 2 ? ` (+${titles.length - 2} more)` : '';
  const what = pasted ? 'The code you just added' : 'This file';
  const pick = await vscode.window.showWarningMessage(
    `LookFirst: ${what} has ${serious.length} serious risk${serious.length === 1 ? '' : 's'}: ${titles.slice(0, 2).join('; ')}${more}`,
    'Show picture', 'Show problems',
  );
  if (pick === 'Show picture') vscode.commands.executeCommand('lookFirst.show');
  if (pick === 'Show problems') vscode.commands.executeCommand('workbench.actions.view.problems');
}

// showStatus counts LookFirst's problems for the document straight from the
// Problems panel, so the shield and the panel can never disagree, and lists
// them in the tooltip.
function showStatus(doc) {
  const items = (diagnostics.get(doc.uri) || []).filter((d) => d.source === 'LookFirst');
  const high = items.filter((d) => d.severity === vscode.DiagnosticSeverity.Error);
  const medium = items.filter((d) => d.severity === vscode.DiagnosticSeverity.Warning);
  if (high.length > 0) {
    status.text = `$(shield) ${high.length} high`;
    status.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
  } else if (medium.length > 0) {
    status.text = `$(shield) ${medium.length} medium`;
    status.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
  } else if (items.length > 0) {
    // Only low findings: worth knowing, nothing to worry about.
    status.text = `$(shield) ${items.length} low`;
    status.backgroundColor = undefined;
  } else {
    status.text = '$(shield) no known risks';
    status.backgroundColor = undefined;
  }
  const level = { [vscode.DiagnosticSeverity.Error]: 'high', [vscode.DiagnosticSeverity.Warning]: 'medium' };
  const lines = items.slice(0, 8).map((d) => `${level[d.severity] || 'low'}, line ${d.range.start.line + 1}: ${d.message.split(': ')[0]}`);
  if (items.length > 8) lines.push(`and ${items.length - 8} more`);
  status.tooltip = `LookFirst, ${path.basename(doc.fileName)}\n${lines.join('\n') || 'No known risks in what we checked.'}\n\nClick to see the picture.`;
  status.show();
}

// show opens the picture for a file or folder from the explorer, or for the
// active editor.
async function show(context, uri) {
  let target;
  let copy;
  let copyOf; // the editor document the scratch copy was made from
  let title;
  if (uri && uri.scheme === 'file') {
    target = uri.fsPath;
    title = path.basename(target);
  } else {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showInformationMessage('LookFirst: open a file, or right-click a file or folder in the explorer.');
      return;
    }
    copy = scratchCopy(editor.document);
    copyOf = editor.document.uri;
    target = copy;
    title = path.basename(editor.document.fileName);
  }

  const out = path.join(scratch, `report-${process.pid}-${Date.now()}.html`);
  let html;
  try {
    const report = await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Window, title: 'LookFirst: reading the code' },
      () => runLookFirst(['read', '--format', 'json', '--vscode-links', '--out', out, target]),
    );
    html = fs.readFileSync(out, 'utf8');
    // Only files that were part of this report can be opened from it. The
    // scratch copy stands for the editor it was copied from.
    for (const src of report.sources) {
      openable.set(key(src), copy && key(src) === key(copy) ? copyOf : vscode.Uri.file(path.resolve(src)));
    }
  } catch (err) {
    vscode.window.showErrorMessage('LookFirst: ' + err.message);
    return;
  } finally {
    if (copy) removeScratch(copy);
    fs.rm(out, { force: true }, () => {});
  }

  // The scratch folder name is an internal detail; show the real file.
  if (copy) html = html.split(escapeHTML(copy)).join(escapeHTML(title));

  const panel = vscode.window.createWebviewPanel('lookFirst', `LookFirst: ${title}`, vscode.ViewColumn.Beside, {
    enableScripts: false,
    enableForms: false,
    // Links in the picture may open the code or ask the AI (which asks the
    // user before sending anything), and nothing else.
    enableCommandUris: ['lookFirst.reveal', 'lookFirst.explain'],
    localResourceRoots: [],
  });
  panel.webview.html = html;
}

// reveal opens a file from the picture at the line of a box or finding.
async function reveal(file, line) {
  const uri = typeof file === 'string' && openable.get(key(file));
  if (!uri) return; // not a file from a report we made
  const n = Math.max(0, (Number(line) || 1) - 1);
  const editor = await vscode.window.showTextDocument(uri, { viewColumn: vscode.ViewColumn.One, preview: false });
  const pos = new vscode.Position(Math.min(n, editor.document.lineCount - 1), 0);
  editor.selection = new vscode.Selection(pos, editor.document.lineAt(pos.line).range.end);
  editor.revealRange(editor.selection, vscode.TextEditorRevealType.InCenter);
}

// key makes paths comparable: absolute, and without case on Windows.
function key(p) {
  const abs = path.resolve(p);
  return process.platform === 'win32' ? abs.toLowerCase() : abs;
}

function scratchCopy(doc) {
  const name = doc.isUntitled ? (LANGUAGE_FILE[doc.languageId] || 'script.txt') : path.basename(doc.fileName);
  const dir = fs.mkdtempSync(path.join(scratch, 'doc-'));
  const file = path.join(dir, name);
  fs.writeFileSync(file, doc.getText(), { mode: 0o600 });
  return file;
}

function removeScratch(file) {
  fs.rm(path.dirname(file), { recursive: true, force: true }, () => {});
}

function programPath() {
  const custom = setting('path');
  if (custom) return custom;
  const exe = process.platform === 'win32' ? '.exe' : '';
  const bundled = path.join(__dirname, 'bin', `lookfirst-${process.platform}-${process.arch}${exe}`);
  if (fs.existsSync(bundled)) {
    // A package built on Windows loses the executable bit.
    if (process.platform !== 'win32') {
      try { fs.chmodSync(bundled, 0o755); } catch { /* read-only install: try anyway */ }
    }
    return bundled;
  }
  return 'lookfirst' + exe;
}

// notFoundMessage says which package to install when the one installed was
// built for another kind of computer, the easiest mistake to make.
function notFoundMessage() {
  const wanted = `${process.platform}-${process.arch}`;
  let other = '';
  try {
    const found = fs.readdirSync(path.join(__dirname, 'bin')).find((f) => f.startsWith('lookfirst-'));
    if (found) other = found.replace(/^lookfirst-/, '').replace(/\.exe$/, '');
  } catch { /* no bin folder */ }
  if (other && other !== wanted) {
    return `this LookFirst package is for ${other} computers, but yours is ${wanted}. `
      + `Uninstall it and install lookfirst-${wanted}-….vsix from the releases page instead.`;
  }
  return 'the lookfirst program was not found. Reinstall the extension, or set lookFirst.path.';
}

// runLookFirst runs the lookfirst program directly, without a shell, and
// returns its JSON report.
function runLookFirst(args) {
  return new Promise((resolve, reject) => {
    cp.execFile(programPath(), args, { timeout: 60000, maxBuffer: 16 * 1024 * 1024, windowsHide: true, cwd: os.tmpdir() },
      (err, stdout, stderr) => {
        if (err) {
          const msg = (stderr || '').replace(/^error:\s*/, '').trim();
          if (err.code === 'ENOENT') {
            reject(new Error(notFoundMessage()));
          } else {
            reject(new Error(msg || err.message));
          }
          return;
        }
        try {
          resolve(JSON.parse(stdout));
        } catch {
          reject(new Error('the lookfirst program gave an answer that could not be read.'));
        }
      });
  });
}

function escapeHTML(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&#34;').replace(/'/g, '&#39;');
}

module.exports = { activate, deactivate };
