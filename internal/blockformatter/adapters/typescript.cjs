'use strict';
// Fixed D5 adapter. T6 is the only permitted process owner.
const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const descriptorBytes = fs.readFileSync(path.join(root, 'provider.json'));
const canonical = value => {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (typeof value === 'object') return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  throw new Error('invalid descriptor value');
};
let descriptor;
try {
  descriptor = JSON.parse(descriptorBytes.toString('utf8'));
  if (Buffer.from(canonical(descriptor), 'utf8').compare(descriptorBytes) !== 0) process.exit(64);
  const required = ['apiVersion','adapter','prettierVersion','compilerVersion','estreeVersion','commentUtilsVersion','nodeVersion','nodeBinarySHA256','files','formatOptions'];
  if (Object.keys(descriptor).sort().join('\0') !== required.slice().sort().join('\0') ||
      descriptor.apiVersion !== 'tplaiter.dev/typescript-provider/v1' || descriptor.adapter !== 'prettier-typescript-standalone-v1' ||
      descriptor.prettierVersion !== '3.9.6' || descriptor.compilerVersion !== '6.0.3' || descriptor.estreeVersion !== '8.65.0' ||
      descriptor.commentUtilsVersion !== '2.5.0' || typeof descriptor.nodeVersion !== 'string' || !/^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/.test(descriptor.nodeVersion) ||
      !/^sha256:[0-9a-f]{64}$/.test(descriptor.nodeBinarySHA256) || !Array.isArray(descriptor.files) || descriptor.files.length !== 4) process.exit(64);
  const filePaths = ['adapter/typescript.cjs','tool/plugins/estree.cjs','tool/plugins/typescript.cjs','tool/standalone.cjs'];
  descriptor.files.forEach((f, i) => {
    if (!f || Object.keys(f).sort().join('\0') !== 'contentSHA256\0mode\0path' || f.path !== filePaths[i] || f.mode !== '100644' || !/^sha256:[0-9a-f]{64}$/.test(f.contentSHA256)) process.exit(64);
  });
  const o = descriptor.formatOptions;
  const optionKeys = ['parser','printWidth','tabWidth','useTabs','semi','singleQuote','quoteProps','jsxSingleQuote','trailingComma','bracketSpacing','bracketSameLine','arrowParens','endOfLine','embeddedLanguageFormatting','proseWrap','requirePragma','insertPragma'];
  if (!o || Object.keys(o).sort().join('\0') !== optionKeys.slice().sort().join('\0') || o.parser !== 'typescript' || o.printWidth !== 80 || o.tabWidth !== 2 || typeof o.useTabs !== 'boolean' || o.useTabs !== false || typeof o.semi !== 'boolean' || o.semi !== true || typeof o.singleQuote !== 'boolean' || o.singleQuote !== false || o.quoteProps !== 'as-needed' || typeof o.jsxSingleQuote !== 'boolean' || o.jsxSingleQuote !== false || o.trailingComma !== 'all' || typeof o.bracketSpacing !== 'boolean' || o.bracketSpacing !== true || typeof o.bracketSameLine !== 'boolean' || o.bracketSameLine !== false || o.arrowParens !== 'always' || o.endOfLine !== 'lf' || o.embeddedLanguageFormatting !== 'off' || o.proseWrap !== 'preserve' || typeof o.requirePragma !== 'boolean' || o.requirePragma !== false || typeof o.insertPragma !== 'boolean' || o.insertPragma !== false) process.exit(64);
} catch (_) { process.exit(64); }
const sha256 = b => 'sha256:' + crypto.createHash('sha256').update(b).digest('hex');
const providerSHA256 = sha256(descriptorBytes);
const [operation, language, logicalPath, suppliedProviderSHA256] = process.argv.slice(2);
const validPath = p => /^[A-Za-z0-9._/-]+$/.test(p) && !p.startsWith('/') && !p.split('/').some(x => x === '' || x === '.' || x === '..');
const validExtension = (lang, p) => lang === 'typescript' ? /\.(ts|mts|cts)$/.test(p) : lang === 'tsx' && p.endsWith('.tsx');
if (!['validate', 'format'].includes(operation) || !['typescript', 'tsx'].includes(language) ||
    Buffer.byteLength(logicalPath, 'utf8') > 4096 || Array.from(logicalPath).length > 1024 ||
    !validPath(logicalPath) || !validExtension(language, logicalPath) || suppliedProviderSHA256 !== providerSHA256) process.exit(64);
const MAX_INPUT_BYTES = 16 * 1024 * 1024;
const readBounded = () => {
  const chunks = []; let total = 0; const chunk = Buffer.allocUnsafe(64 * 1024);
  for (;;) { const n = fs.readSync(0, chunk, 0, chunk.length, null); if (n === 0) break; total += n; if (total > MAX_INPUT_BYTES) process.exit(66); chunks.push(Buffer.from(chunk.subarray(0, n))); }
  return Buffer.concat(chunks, total);
};
let rawInput; try { rawInput = readBounded(); } catch (_) { process.exit(66); }
let input; try { input = new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(rawInput); } catch (_) { process.exit(66); }
let prettier, typescript, estree;
try {
  prettier = require(path.join(root, 'tool', 'standalone.cjs'));
  typescript = require(path.join(root, 'tool', 'plugins', 'typescript.cjs'));
  estree = require(path.join(root, 'tool', 'plugins', 'estree.cjs'));
} catch (_) { process.exit(65); }
const options = {...descriptor.formatOptions, parser: 'typescript', filepath: logicalPath, plugins: [typescript, estree]};
const parserResult = () => {
  let ast;
  try { ast = typescript.parsers.typescript.parse(input, options); } catch (_) { process.exit(65); }
  if (!ast || ast.type !== 'Program' || !Array.isArray(ast.comments)) process.exit(65);
  if (ast.comments.length > 65536) process.exit(66);
  const utf16ToByte = [0];
  for (let i = 0; i < input.length; i++) utf16ToByte.push(Buffer.byteLength(input.slice(0, i + 1), 'utf8'));
  let previous = -1; let previousEnd = -1;
  const comments = ast.comments.map(c => {
    if (!c || (c.type !== 'Line' && c.type !== 'Block') || !Number.isInteger(c.range?.[0]) || !Number.isInteger(c.range?.[1])) process.exit(65);
    const [start, end] = c.range;
    if (start < 0 || start >= end || end > input.length || start <= previous || start < previousEnd ||
        (start > 0 && start < input.length && input.charCodeAt(start) >= 0xdc00 && input.charCodeAt(start) <= 0xdfff) ||
        (end > 0 && end < input.length && input.charCodeAt(end) >= 0xdc00 && input.charCodeAt(end) <= 0xdfff)) process.exit(65);
    const raw = input.slice(start, end);
    if (c.type === 'Line' ? !raw.startsWith('//') : !raw.startsWith('/*') || !raw.endsWith('*/')) process.exit(65);
    previous = start; previousEnd = end;
    return {kind: c.type === 'Line' ? 'line' : 'block', startByte: utf16ToByte[start], endByte: utf16ToByte[end]};
  });
  if (input.startsWith('#!') && comments[0]?.startByte === 0) comments.shift();
  return comments;
};
if (operation === 'format') { prettier.format(input, options).then(x => process.stdout.write(x), () => process.exit(65)); }
else { process.stdout.write(JSON.stringify({apiVersion:'tplaiter.dev/typescript-comments/v1',language,path:logicalPath,inputSHA256:sha256(rawInput),providerSHA256,comments:parserResult()})); }
