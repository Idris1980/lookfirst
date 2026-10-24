package script

import "strings"

// These lists are built in so the check works offline. They are not
// complete: a package missing from them is not bad, only worth a look.

var pythonStdlib = set(`__future__ abc argparse array ast asyncio atexit base64 binascii bisect builtins bz2
calendar cgi cmath cmd codecs collections colorsys concurrent configparser contextlib contextvars copy
copyreg cProfile csv ctypes curses dataclasses datetime dbm decimal difflib dis doctest email encodings
enum errno faulthandler fcntl filecmp fileinput fnmatch fractions ftplib functools gc getopt getpass
gettext glob graphlib grp gzip hashlib heapq hmac html http imaplib importlib inspect io ipaddress
itertools json keyword linecache locale logging lzma mailbox marshal math mimetypes mmap msvcrt
multiprocessing netrc numbers operator optparse os pathlib pdb pickle pkgutil platform plistlib poplib
posix pprint profile pstats pty pwd py_compile queue quopri random re readline reprlib resource rlcompleter
runpy sched secrets select selectors shelve shlex shutil signal site smtplib socket socketserver sqlite3
ssl stat statistics string stringprep struct subprocess symtable sys sysconfig syslog tabnanny tarfile
tempfile termios textwrap threading time timeit tkinter token tokenize tomllib trace traceback tracemalloc
tty turtle types typing unicodedata unittest urllib uuid venv warnings wave weakref webbrowser winreg
winsound wsgiref xml xmlrpc zipapp zipfile zipimport zlib zoneinfo _thread`)

var nodeBuiltins = set(`assert async_hooks buffer child_process cluster console constants crypto dgram dns
domain events fs http http2 https inspector module net os path perf_hooks process punycode querystring
readline repl stream string_decoder sys timers tls trace_events tty url util v8 vm wasi worker_threads zlib
test sqlite`)

// Python packages as they are installed (pip names) and imported, where the
// two differ the import name maps to the pip name.
var pythonImportToPip = map[string]string{
	"yaml": "pyyaml", "cv2": "opencv-python", "PIL": "pillow", "sklearn": "scikit-learn", "bs4": "beautifulsoup4",
	"dateutil": "python-dateutil", "dotenv": "python-dotenv", "jwt": "pyjwt", "Crypto": "pycryptodome",
	"OpenSSL": "pyopenssl", "magic": "python-magic", "docx": "python-docx", "pptx": "python-pptx",
	"serial": "pyserial", "usb": "pyusb", "git": "gitpython", "attr": "attrs", "google": "google-api-python-client",
	"jose": "python-jose", "multipart": "python-multipart", "socketio": "python-socketio", "telegram": "python-telegram-bot",
	"psycopg2": "psycopg2-binary", "MySQLdb": "mysqlclient", "win32api": "pywin32", "win32com": "pywin32",
	"azure": "azure-identity", "skimage": "scikit-image", "fitz": "pymupdf", "discord": "discord.py",
}

var pythonPopular = set(`requests numpy pandas boto3 botocore urllib3 setuptools certifi idna charset-normalizer
typing-extensions python-dateutil s3transfer packaging six pyyaml pip cryptography wheel attrs
cffi pycparser jmespath rsa pyasn1 google-api-core protobuf platformdirs click jinja2 markupsafe pydantic
pydantic-core importlib-metadata zipp filelock pytz tomli virtualenv aiohttp yarl multidict frozenlist
aiosignal async-timeout wrapt pyjwt psutil grpcio pluggy pytest iniconfig exceptiongroup soupsieve
beautifulsoup4 lxml pillow scipy matplotlib kiwisolver cycler fonttools pyparsing contourpy decorator
sqlalchemy greenlet tqdm openpyxl et-xmlfile werkzeug flask itsdangerous blinker fastapi starlette uvicorn
anyio sniffio h11 httpx httpcore gunicorn django asgiref sqlparse redis pymongo psycopg2 psycopg2-binary
psycopg mysqlclient pymysql scikit-learn joblib threadpoolctl tensorflow keras torch torchvision torchaudio
transformers tokenizers huggingface-hub safetensors regex sentencepiece datasets openai anthropic tiktoken
langchain langchain-core langchain-community langchain-openai langchain-anthropic llama-index chromadb
faiss-cpu pinecone-client sentence-transformers selenium playwright scrapy paramiko fabric invoke docker
kubernetes azure-identity azure-core azure-storage-blob azure-keyvault-secrets azure-mgmt-resource
azure-functions google-cloud-storage google-auth google-api-python-client python-dotenv pyopenssl
pycryptodome bcrypt passlib python-jose python-multipart marshmallow celery kombu billiard vine
alembic mako opencv-python opencv-python-headless scikit-image sympy networkx seaborn plotly dash
streamlit gradio jupyter notebook ipython ipykernel black flake8 pylint mypy isort ruff coverage tox
nox pre-commit rich typer colorama termcolor tabulate loguru structlog sentry-sdk prometheus-client
pyserial pyusb gitpython pyinstaller cython numba pyarrow polars duckdb xlrd xlsxwriter python-docx
python-pptx reportlab pypdf pypdf2 pymupdf markdown mistune docutils sphinx mkdocs feedparser
websocket-client websockets python-socketio discord.py python-telegram-bot tweepy slack-sdk twilio
stripe pywin32 pyautogui pynput keyboard mouse schedule apscheduler arrow pendulum orjson ujson
simplejson msgpack toml tomlkit jsonschema cerberus voluptuous boto s3fs fsspec gcsfs pexpect
sh plumbum ansible netmiko scapy dnspython geopy shapely pyproj folium nltk spacy gensim textblob
pyjwt oauthlib requests-oauthlib authlib httplib2 uritemplate cachetools tenacity backoff retry
attrs cattrs mock responses faker factory-boy hypothesis pytest-cov pytest-mock pytest-asyncio
python-magic chardet unidecode emoji qrcode pyqrcode pyotp keyring`)

var npmPopular = set(`react react-dom next vue nuxt svelte @sveltejs/kit angular @angular/core express koa fastify
hapi @hapi/hapi nestjs @nestjs/core lodash underscore axios node-fetch got ky superagent request
moment dayjs date-fns luxon chalk commander yargs inquirer ora debug dotenv cross-env uuid nanoid
classnames clsx zod yup joi ajv typescript ts-node tsx esbuild vite webpack rollup parcel babel
@babel/core @babel/preset-env eslint prettier jest vitest mocha chai sinon supertest cypress
playwright @playwright/test puppeteer jsdom cheerio body-parser cors helmet morgan cookie-parser
express-session passport jsonwebtoken bcrypt bcryptjs argon2 mongoose mongodb mysql mysql2 pg
sequelize typeorm prisma @prisma/client knex redis ioredis socket.io socket.io-client ws
graphql apollo-server @apollo/client multer sharp jimp nodemailer winston pino bunyan rxjs
redux @reduxjs/toolkit react-redux zustand jotai mobx react-router react-router-dom
@tanstack/react-query swr tailwindcss postcss autoprefixer sass styled-components @emotion/react
@mui/material antd bootstrap jquery three d3 chart.js recharts openai @anthropic-ai/sdk langchain
@langchain/core @langchain/openai ai firebase firebase-admin @supabase/supabase-js aws-sdk
@aws-sdk/client-s3 @azure/identity @azure/storage-blob googleapis stripe twilio discord.js
telegraf node-cron cron bull bullmq amqplib kafkajs dockerode ssh2 shelljs execa glob rimraf
fs-extra chokidar nodemon pm2 concurrently minimist semver yaml js-yaml xml2js csv-parse
papaparse xlsx pdfkit pdf-lib marked markdown-it highlight.js prismjs qs querystring-es3
http-proxy http-proxy-middleware compression serve-static ejs pug handlebars nunjucks
electron electron-builder vscode @types/node @types/react @types/express @types/vscode
crypto-js node-forge jose qrcode validator sanitize-html dompurify isomorphic-dompurify
p-limit p-queue async bluebird immer ramda date-fns-tz colors kleur picocolors`)

func set(words string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(words) {
		m[strings.ToLower(w)] = true
	}
	return m
}

// lookalike returns a well-known package whose name is one or two typing
// mistakes away from name, the trick behind typosquatting.
func lookalike(name string, popular map[string]bool) (string, bool) {
	n := normalize(name)
	if len(n) < 4 {
		return "", false
	}
	for p := range popular {
		pn := normalize(p)
		if pn == n {
			return "", false // same package, written with - or _
		}
	}
	best, bestDist := "", 3
	for p := range popular {
		pn := normalize(p)
		if abs(len(pn)-len(n)) > 2 {
			continue
		}
		d := distance(n, pn)
		limit := 1
		if len(pn) >= 8 {
			limit = 2
		}
		if d <= limit && d < bestDist {
			best, bestDist = p, d
		}
	}
	return best, best != ""
}

func normalize(s string) string {
	return strings.NewReplacer("_", "-", ".", "-").Replace(strings.ToLower(s))
}

// distance is the Damerau-Levenshtein distance (with swaps), small inputs only.
func distance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	d := make([][]int, len(ra)+1)
	for i := range d {
		d[i] = make([]int, len(rb)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ra)][len(rb)]
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
