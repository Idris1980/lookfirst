// "Explain and fix with AI": asks the language model the user already has in
// VS Code (for example GitHub Copilot) to explain one finding and suggest a
// fix. Nothing is sent until the user has turned the feature on and has seen
// exactly what will be sent, with passwords and keys replaced by
// placeholders. A suggested fix changes the file only when the user applies
// it, after seeing the change.
//
// The model is the one in VS Code (the default) or, for those who choose it
// with lookFirst.ai.provider, Claude: through the Claude Code program they
// are signed in to (their Claude plan), or through the Anthropic API with
// their own key, kept in VS Code's secret storage.
const vscode = require('vscode');
const os = require('os');
const path = require('path');
const ai = require('./ai');
const anthropic = require('./anthropic');
const claudeCode = require('./claudecode');

const SCHEME = 'lookfirst-ai';
const KEY_STORAGE_ID = 'lookFirst.anthropicApiKey';
let secrets; // VS Code's secret storage, set in register
const fixes = new Map(); // id -> { uri, version, start, end, after, title }
const virtualDocs = new Map(); // virtual document path -> text
let nextId = 1;

function register(context, h) {
  secrets = context.secrets;
  const onDidChange = new vscode.EventEmitter();
  context.subscriptions.push(
    vscode.commands.registerCommand('lookFirst.setAnthropicKey', () => askForKey()),
    vscode.commands.registerCommand('lookFirst.removeAnthropicKey', async () => {
      await secrets.delete(KEY_STORAGE_ID);
      vscode.window.showInformationMessage('LookFirst: the Anthropic API key was removed from this computer.');
    }),
    onDidChange,
    vscode.workspace.registerTextDocumentContentProvider(SCHEME, {
      onDidChange: onDidChange.event,
      provideTextDocumentContent: (uri) => virtualDocs.get(uri.path) || '',
    }),
    vscode.commands.registerCommand('lookFirst.explain', (target, line, title, detail) => explain(h, target, line, title, detail)),
    vscode.commands.registerCommand('lookFirst.showFix', (id) => showFix(id)),
    vscode.commands.registerCommand('lookFirst.applyFix', (id) => applyFix(id)),
    vscode.languages.registerCodeActionsProvider([{ scheme: 'file' }, { scheme: 'untitled' }], { provideCodeActions }, {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
    }),
  );
}

// Offer the AI on every LookFirst problem in the editor (the light bulb).
function provideCodeActions(doc, _range, context) {
  const actions = [];
  for (const d of context.diagnostics) {
    if (d.source !== 'LookFirst') continue;
    const [title, ...rest] = d.message.split(': ');
    const action = new vscode.CodeAction(`LookFirst: explain and fix with AI (${title})`, vscode.CodeActionKind.QuickFix);
    action.diagnostics = [d];
    action.command = { command: 'lookFirst.explain', title: action.title, arguments: [doc.uri, d.range.start.line + 1, title, rest.join(': ')] };
    actions.push(action);
  }
  return actions;
}

async function explain(h, target, line, title, detail) {
  // Where the request comes from: a light bulb (a URI), a link in the
  // picture (a path from the report), or the command palette (nothing).
  let uri;
  if (target instanceof vscode.Uri) {
    uri = target;
  } else if (typeof target === 'string') {
    uri = h.openable.get(h.key(target));
    if (!uri) return; // not a file from a report we made
  } else {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;
    uri = editor.document.uri;
    line = editor.selection.active.line + 1;
    const d = vscode.languages.getDiagnostics(uri).find((x) => x.source === 'LookFirst' && x.range.start.line === line - 1);
    if (!d) {
      vscode.window.showInformationMessage('LookFirst: put the cursor on a line with a LookFirst problem first.');
      return;
    }
    [title, ...detail] = d.message.split(': ');
    detail = detail.join(': ');
  }
  if (typeof title !== 'string' || typeof detail !== 'string' || !Number.isInteger(Number(line))) return;
  line = Number(line);

  if (!(await optIn())) return;

  const doc = await vscode.workspace.openTextDocument(uri);
  let excerpt;
  const copy = h.scratchCopy(doc);
  try {
    excerpt = await h.runLookFirst(['excerpt', '--line', String(line), '--context', '15', copy]);
  } catch (err) {
    vscode.window.showErrorMessage('LookFirst: ' + err.message);
    return;
  } finally {
    h.removeScratch(copy);
  }

  const model = await chooseModel();
  if (!model) return;

  const fileName = path.basename(doc.fileName);
  const prompt = ai.buildPrompt({
    title, detail, fileName, languageId: doc.languageId, excerpt: excerpt.text,
    start: excerpt.start, end: excerpt.end, line: excerpt.line, answerLanguage: ai.languageName(vscode.env.language),
  });
  if (!(await confirmSend(prompt, model, Object.keys(excerpt.secrets || {}).length))) return;

  let reply = '';
  try {
    await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: `LookFirst: asking ${model.name}`,
      cancellable: true,
    }, async (_progress, token) => {
      reply = await model.ask(prompt, token);
      if (token.isCancellationRequested) reply = null;
    });
    if (reply === null) return;
  } catch (err) {
    vscode.window.showErrorMessage('LookFirst: the AI model could not answer: ' + (err && err.message ? err.message : String(err)));
    return;
  }

  const answer = ai.parseAnswer(reply);
  const id = String(nextId++);
  if (answer.code !== null) {
    const fixed = ai.restoreSecrets(answer.code, excerpt.secrets);
    fixes.set(id, {
      uri, title, fileName, version: doc.version, start: excerpt.start, end: excerpt.end,
      after: ai.replaceLines(doc.getText(), excerpt.start, excerpt.end, fixed),
    });
  }

  const panel = vscode.window.createWebviewPanel('lookFirstAI', `LookFirst AI: ${fileName}`, vscode.ViewColumn.Beside, {
    enableScripts: false,
    enableForms: false,
    // The answer page may run these two commands and nothing else.
    enableCommandUris: ['lookFirst.showFix', 'lookFirst.applyFix'],
    localResourceRoots: [],
  });
  const arg = encodeURIComponent(JSON.stringify([id]));
  const modelName = model.used ? `${model.name}, ${model.used.toLocaleString('en')} tokens` : model.name;
  panel.webview.html = ai.answerHTML({
    title, fileName, modelName, explanation: answer.explanation || '(no explanation)', code: answer.code,
    showHref: `command:lookFirst.showFix?${arg}`, applyHref: `command:lookFirst.applyFix?${arg}`,
  });
  panel.onDidDispose(() => fixes.delete(id));
}

// chooseModel returns { name, ask(prompt, token) } for the provider the user
// chose, or undefined when there is nothing to ask.
async function chooseModel() {
  const config = vscode.workspace.getConfiguration('lookFirst');
  const wanted = config.get('ai.model');

  if (config.get('ai.provider') === 'claude-code') {
    const ext = vscode.extensions.getExtension('anthropic.claude-code');
    const extensionsDir = ext ? path.dirname(ext.extensionPath) : path.join(os.homedir(), '.vscode', 'extensions');
    const bin = claudeCode.find(config.get('ai.claudePath'), extensionsDir);
    if (!bin) {
      vscode.window.showWarningMessage('LookFirst: the Claude Code program was not found. Install Claude Code and sign in with your Claude account, or set its full path in the setting lookFirst.ai.claudePath.');
      return undefined;
    }
    const modelName = claudeCode.model(wanted);
    const model = {
      name: `Claude${modelName ? ' ' + ai.modelLabel(modelName).replace(/^Claude /, '') : ''} through Claude Code (your Claude plan)`,
      ask: async (prompt, token) => {
        const reply = await claudeCode.ask({ bin, modelName, prompt, onCancel: (stop) => token.onCancellationRequested(stop) });
        model.used = claudeCode.tokens(reply.usage);
        return reply.text;
      },
    };
    return model;
  }

  if (config.get('ai.provider') === 'anthropic') {
    let apiKey = await secrets.get(KEY_STORAGE_ID);
    if (!apiKey) apiKey = await askForKey();
    if (!apiKey) return undefined;
    const id = ai.anthropicModel(wanted);
    return {
      name: `${ai.modelLabel(id)} (Anthropic API, your key)`,
      ask: async (prompt) => (await anthropic.ask({ apiKey, model: id, prompt })).text,
    };
  }

  const models = await vscode.lm.selectChatModels();
  if (models.length === 0) {
    vscode.window.showWarningMessage('LookFirst: there is no AI model in VS Code to ask. Install and sign in to GitHub Copilot, or another extension that provides a language model, or choose Anthropic in the setting lookFirst.ai.provider.');
    return undefined;
  }
  const model = ai.pickModel(models, wanted);
  return {
    name: ai.vscodeModelLabel(model),
    ask: async (prompt, token) => {
      const response = await model.sendRequest([vscode.LanguageModelChatMessage.User(prompt)], {
        justification: 'LookFirst sends a short piece of code around one problem, with passwords and keys replaced, to explain the problem and suggest a fix.',
      }, token);
      let text = '';
      for await (const chunk of response.text) text += chunk;
      return text;
    },
  };
}

// askForKey asks for an Anthropic API key and keeps it in VS Code's secret
// storage, encrypted by the operating system. It is never shown again.
async function askForKey() {
  const key = await vscode.window.showInputBox({
    title: 'LookFirst: Anthropic API key',
    prompt: 'Paste an API key from console.anthropic.com. It is stored encrypted on this computer and only sent to Anthropic. Use is billed to that Anthropic account.',
    password: true,
    ignoreFocusOut: true,
    placeHolder: 'sk-ant-…',
    validateInput: (v) => (/^sk-ant-\S{20,}$/.test(v.trim()) ? undefined : 'An Anthropic API key starts with sk-ant-'),
  });
  if (!key) return undefined;
  await secrets.store(KEY_STORAGE_ID, key.trim());
  vscode.window.showInformationMessage('LookFirst: the Anthropic API key is saved. Remove it any time with "LookFirst: Remove Anthropic API Key".');
  return key.trim();
}

// optIn asks once whether the feature may be used at all.
async function optIn() {
  const config = vscode.workspace.getConfiguration('lookFirst');
  if (config.get('ai.enabled')) return true;
  const pick = await vscode.window.showInformationMessage(
    'Use AI to explain problems and suggest fixes?',
    {
      modal: true,
      detail: 'LookFirst can ask an AI model to explain a problem and suggest a fix: the one you already use in VS Code, for example GitHub Copilot, or Claude, through the Claude Code program you are signed in to or your own Anthropic API key, if you choose that in the setting lookFirst.ai.provider. '
        + 'It sends about 30 lines of code around the problem, with passwords and keys replaced by placeholders such as «SECRET_1». '
        + 'You see exactly what will be sent each time, and nothing is sent unless you choose Send. You can turn this off with the setting lookFirst.ai.enabled.',
    },
    'Turn on',
  );
  if (pick !== 'Turn on') return false;
  await config.update('ai.enabled', true, vscode.ConfigurationTarget.Global);
  return true;
}

// confirmSend shows the request, exactly as it will be sent, in a read-only
// editor, and asks before sending it.
async function confirmSend(prompt, model, secretCount) {
  const config = vscode.workspace.getConfiguration('lookFirst');
  if (!config.get('ai.showBeforeSending')) return true;

  const docPath = `/request-${nextId}.md`;
  virtualDocs.set(docPath, prompt);
  const uri = vscode.Uri.from({ scheme: SCHEME, path: docPath });
  const doc = await vscode.workspace.openTextDocument(uri);
  await vscode.window.showTextDocument(doc, { viewColumn: vscode.ViewColumn.Beside, preview: true, preserveFocus: false });

  const masked = secretCount === 0
    ? 'No passwords or keys were found in this piece of code.'
    : `${secretCount} password${secretCount === 1 ? '' : 's'} or key${secretCount === 1 ? '' : 's'} were replaced with placeholders.`;
  const pick = await vscode.window.showInformationMessage(
    `Send this to ${model.name}?`,
    { modal: true, detail: `The text that will be sent is open in the editor. ${masked} Check that nothing else private is in it.` },
    'Send', 'Send, and stop asking',
  );

  for (const group of vscode.window.tabGroups.all) {
    for (const tab of group.tabs) {
      if (tab.input instanceof vscode.TabInputText && tab.input.uri.toString() === uri.toString()) {
        await vscode.window.tabGroups.close(tab);
      }
    }
  }
  virtualDocs.delete(docPath);

  if (pick === 'Send, and stop asking') {
    await config.update('ai.showBeforeSending', false, vscode.ConfigurationTarget.Global);
  }
  return pick === 'Send' || pick === 'Send, and stop asking';
}

async function showFix(id) {
  const fix = fixes.get(String(id));
  if (!fix) return;
  const afterPath = `/fix-${id}/${fix.fileName}`;
  virtualDocs.set(afterPath, fix.after);
  const after = vscode.Uri.from({ scheme: SCHEME, path: afterPath });
  await vscode.commands.executeCommand('vscode.diff', fix.uri, after, `LookFirst: suggested fix for ${fix.fileName}`, { viewColumn: vscode.ViewColumn.One });
}

async function applyFix(id) {
  const fix = fixes.get(String(id));
  if (!fix) return;
  const doc = await vscode.workspace.openTextDocument(fix.uri);
  if (doc.version !== fix.version) {
    vscode.window.showWarningMessage('LookFirst: the file has changed since the AI answered, so the fix was not applied. Ask again to get a fix for the current code.');
    return;
  }
  const pick = await vscode.window.showWarningMessage(
    `Apply the suggested fix to ${fix.fileName}?`,
    { modal: true, detail: 'The suggestion comes from an AI model and can be wrong. Look at the change first (Show the change). You can undo it with Ctrl+Z.' },
    'Apply',
  );
  if (pick !== 'Apply') return;
  const edit = new vscode.WorkspaceEdit();
  const whole = new vscode.Range(doc.positionAt(0), doc.positionAt(doc.getText().length));
  edit.replace(fix.uri, whole, fix.after);
  if (await vscode.workspace.applyEdit(edit)) {
    fixes.delete(String(id));
    await vscode.window.showTextDocument(doc, { viewColumn: vscode.ViewColumn.One, selection: new vscode.Range(fix.start - 1, 0, fix.start - 1, 0) });
    vscode.window.showInformationMessage(`LookFirst: the fix was applied to ${fix.fileName}. Save the file to keep it, or press Ctrl+Z to undo.`);
  }
}

module.exports = { register };
