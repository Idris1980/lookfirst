// The page's own script. It loads the LookFirst reader (WebAssembly) and
// hands it the code the visitor pastes, opens or picks. Nothing is sent
// anywhere: the Content-Security-Policy only lets the page load its own files.
'use strict';

const MAX_FILE = 2 * 1024 * 1024; // the reader's own limits
const MAX_FILES = 500;
const SKIP = /(^|\/)(node_modules|\.git|\.terraform|\.venv|venv|__pycache__|dist|build|vendor|\.next)\//;

const $ = (id) => document.getElementById(id);
let ready = false;
let reportURL = null;

function status(text, isError) {
  const el = $('status');
  el.textContent = text;
  el.classList.toggle('error', !!isError);
}

async function load() {
  const go = new Go();
  const result = await WebAssembly.instantiateStreaming(fetch('lookfirst.wasm?v=__BUILD__'), go.importObject);
  go.run(result.instance);
  ready = true;
  $('run-paste').disabled = false;
  status('Ready. Nothing you check here leaves your browser.');
}

function run(files) {
  if (!ready) return;
  if (files.length === 0) {
    status('There was nothing to read.', true);
    return;
  }
  status('Reading…');
  // Let the status show before the work starts.
  setTimeout(() => {
    const reply = JSON.parse(window.lookfirstRead(JSON.stringify(files)));
    if (reply.error) {
      status(reply.error, true);
      return;
    }
    const frame = $('report');
    // The report goes in as a file in the browser's memory (a blob: address)
    // rather than as srcdoc, so its own links, such as the overview's
    // "#project-2", stay inside the report instead of loading this page.
    if (reportURL) URL.revokeObjectURL(reportURL);
    reportURL = URL.createObjectURL(new Blob([reply.html], { type: 'text/html' }));
    frame.src = reportURL;
    $('result').hidden = false;
    status(`Read ${files.length} file${files.length === 1 ? '' : 's'}. The report is below.`);
    $('result').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 30);
}

// Paste
$('run-paste').addEventListener('click', () => {
  const text = $('code').value;
  if (!text.trim()) {
    status('Paste some code first.', true);
    return;
  }
  const name = $('kind').value || window.lookfirstGuessName(text);
  if (!name) {
    status('Could not tell what kind of code this is. Choose it in the list.', true);
    $('kind').focus();
    return;
  }
  run([{ name, text }]);
});

// Files and folders
async function readPicked(list) {
  const files = [];
  let skipped = 0;
  for (const f of list) {
    const name = f.webkitRelativePath || f.name;
    if (SKIP.test(name)) continue;
    if (f.size > MAX_FILE) {
      skipped++;
      continue;
    }
    if (files.length >= MAX_FILES) break;
    files.push({ name, text: await f.text() });
  }
  if (skipped) status(`${skipped} file${skipped === 1 ? ' was' : 's were'} larger than 2 MB and skipped.`);
  run(files);
}
$('pick-files').addEventListener('change', (e) => readPicked(e.target.files));
$('pick-folder').addEventListener('change', (e) => readPicked(e.target.files));

// Examples
for (const ex of window.LOOKFIRST_EXAMPLES || []) {
  const b = document.createElement('button');
  b.className = 'example';
  const strong = document.createElement('strong');
  strong.textContent = ex.title;
  const span = document.createElement('span');
  span.textContent = ex.files.map((f) => f.name.split('/').pop()).join(', ');
  b.append(strong, span);
  b.addEventListener('click', () => run(ex.files));
  $('examples').append(b);
}

// Tabs
const tabs = ['paste', 'files', 'examples'];
for (const t of tabs) {
  $(`tab-${t}`).addEventListener('click', () => {
    for (const u of tabs) {
      $(`tab-${u}`).setAttribute('aria-selected', String(u === t));
      $(`panel-${u}`).hidden = u !== t;
    }
  });
}

// A link such as #example=python-helper opens the page with that example.
function exampleFromLink() {
  const m = location.hash.match(/^#example=([\w-]+)$/);
  if (!m) return;
  const ex = (window.LOOKFIRST_EXAMPLES || []).find((e) => e.files[0] && e.files[0].name.startsWith(m[1] + '/'));
  if (ex) run(ex.files);
}

load()
  .then(exampleFromLink)
  .catch((err) => status('The reader could not be loaded: ' + err.message, true));
