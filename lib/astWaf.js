// AST and structural tokenizer for WAF payload analysis

// SQL Keywords
const SQL_KEYWORDS = new Set([
  'UNION', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'TRUNCATE',
  'ALTER', 'EXEC', 'EXECUTE', 'INFORMATION_SCHEMA', 'SLEEP', 'BENCHMARK',
  'WAITFOR', 'XP_CMDSHELL', 'EXTRACTVALUE', 'UPDATEXML', 'AND', 'OR', 'FROM', 'WHERE'
]);

/**
 * SQL Lexer: converts a string into structural tokens
 */
function tokenizeSql(str) {
  if (!str || typeof str !== 'string') return [];
  const tokens = [];
  let i = 0;
  const len = str.length;

  while (i < len) {
    const ch = str[i];

    // Whitespace
    if (/\s/.test(ch)) {
      i++;
      continue;
    }

    // Inline block comments /* ... */
    if (ch === '/' && str[i + 1] === '*') {
      const start = i;
      i += 2;
      while (i < len && !(str[i] === '*' && str[i + 1] === '/')) i++;
      i += 2;
      tokens.push({ type: 'COMMENT', value: str.slice(start, i) });
      continue;
    }

    // Line comments -- or #
    if ((ch === '-' && str[i + 1] === '-') || ch === '#') {
      const start = i;
      while (i < len && str[i] !== '\n' && str[i] !== '\r') i++;
      tokens.push({ type: 'COMMENT', value: str.slice(start, i) });
      continue;
    }

    // String literals '...' or "..."
    if (ch === "'" || ch === '"') {
      const quote = ch;
      const start = i;
      i++;
      while (i < len && str[i] !== quote) {
        if (str[i] === '\\') i++; // escaped quote
        i++;
      }
      i++;
      tokens.push({ type: 'STRING', value: str.slice(start, i) });
      continue;
    }

    // Numbers
    if (/\d/.test(ch)) {
      const start = i;
      while (i < len && /\d/.test(str[i])) i++;
      tokens.push({ type: 'NUMBER', value: str.slice(start, i) });
      continue;
    }

    // Operators & Symbols
    if (/^(=|!=|<>|<|>|<=|>=|;|,|\(|\)|\+|-|\*|\/)/.test(str.slice(i))) {
      const match = str.slice(i).match(/^(=|!=|<>|<|>|<=|>=|;|,|\(|\)|\+|-|\*|\/)/)[0];
      tokens.push({ type: 'OPERATOR', value: match });
      i += match.length;
      continue;
    }

    // Identifiers & Keywords
    if (/[a-zA-Z_]/.test(ch)) {
      const start = i;
      while (i < len && /[a-zA-Z0-9_]/.test(str[i])) i++;
      const val = str.slice(start, i);
      const upper = val.toUpperCase();
      if (SQL_KEYWORDS.has(upper)) {
        tokens.push({ type: 'KEYWORD', value: upper, raw: val });
      } else {
        tokens.push({ type: 'IDENTIFIER', value: val });
      }
      continue;
    }

    // Any other char
    tokens.push({ type: 'SYMBOL', value: ch });
    i++;
  }

  return tokens;
}

/**
 * Inspect SQL AST structures
 */
function inspectSqlAst(str, source) {
  const hits = [];
  const tokens = tokenizeSql(str);
  const nonCommentTokens = tokens.filter((t) => t.type !== 'COMMENT');

  // 1. Tautology Detection: LITERAL OPERATOR LITERAL (e.g. 1=1 or 'a'='a')
  for (let i = 0; i < nonCommentTokens.length - 2; i++) {
    const t1 = nonCommentTokens[i];
    const op = nonCommentTokens[i + 1];
    const t2 = nonCommentTokens[i + 2];

    if (op.type === 'OPERATOR' && (op.value === '=' || op.value === '!=' || op.value === '<>')) {
      if ((t1.type === 'NUMBER' && t2.type === 'NUMBER' && t1.value === t2.value) ||
          (t1.type === 'STRING' && t2.type === 'STRING' && t1.value === t2.value)) {
        hits.push({
          id: 'ast_sqli_tautology',
          family: 'SQLi (AST)',
          label: `AST Tautology [${t1.value} ${op.value} ${t2.value}]`,
          score: 4,
          source,
        });
        break;
      }
    }
  }

  // 2. UNION SELECT Token Sequence (regardless of comments or whitespace)
  const unionIdx = nonCommentTokens.findIndex((t) => t.type === 'KEYWORD' && t.value === 'UNION');
  if (unionIdx !== -1) {
    const nextSelect = nonCommentTokens.slice(unionIdx + 1).find((t) => t.type === 'KEYWORD' && t.value === 'SELECT');
    if (nextSelect) {
      hits.push({
        id: 'ast_sqli_union_select',
        family: 'SQLi (AST)',
        label: 'AST Structural UNION SELECT',
        score: 4,
        source,
      });
    }
  }

  // 3. Stacked Command Execution: ; -> KEYWORD
  const semiIdx = nonCommentTokens.findIndex((t) => t.type === 'OPERATOR' && t.value === ';');
  if (semiIdx !== -1 && semiIdx < nonCommentTokens.length - 1) {
    const nextToken = nonCommentTokens[semiIdx + 1];
    if (nextToken.type === 'KEYWORD' && ['DROP', 'TRUNCATE', 'DELETE', 'UPDATE', 'EXEC', 'EXECUTE', 'SELECT'].includes(nextToken.value)) {
      hits.push({
        id: 'ast_sqli_stacked',
        family: 'SQLi (AST)',
        label: `AST Stacked Command [; ${nextToken.value}]`,
        score: 4,
        source,
      });
    }
  }

  return hits;
}

/**
 * Inspect HTML / DOM AST structures
 */
function inspectDomAst(str, source) {
  const hits = [];

  // 1. Tag tokenization (element tags)
  const tagMatches = str.match(/<\s*([a-zA-Z0-9]+)[^>]*>/gi);
  if (tagMatches) {
    for (const tag of tagMatches) {
      const tagNameMatch = tag.match(/<\s*([a-zA-Z0-9]+)/);
      const tagName = tagNameMatch ? tagNameMatch[1].toLowerCase() : '';
      if (['script', 'iframe', 'svg', 'object', 'embed', 'body', 'applet'].includes(tagName)) {
        hits.push({
          id: `ast_xss_tag_${tagName}`,
          family: 'XSS (AST)',
          label: `AST DOM Element Tag <${tagName}>`,
          score: 4,
          source,
        });
      }
    }
  }

  // 2. Inline event handler attribute AST check
  const eventAttrMatch = str.match(/\bon[a-z]+\s*=/gi);
  if (eventAttrMatch) {
    for (const attr of eventAttrMatch) {
      const name = attr.replace(/\s*=/, '').toLowerCase();
      hits.push({
        id: `ast_xss_attr_${name}`,
        family: 'XSS (AST)',
        label: `AST Event Handler Attribute [${name}]`,
        score: 3,
        source,
      });
    }
  }

  // 3. Javascript URI Scheme
  if (/javascript\s*:/i.test(str)) {
    hits.push({
      id: 'ast_xss_js_protocol',
      family: 'XSS (AST)',
      label: 'AST javascript: Protocol Scheme',
      score: 3,
      source,
    });
  }

  return hits;
}

/**
 * Main AST Inspector function
 */
function inspectAst(str, source = 'unknown') {
  if (typeof str !== 'string' || str.length === 0) return [];
  const sqlHits = inspectSqlAst(str, source);
  const domHits = inspectDomAst(str, source);

  // Deduplicate hits by id
  const seen = new Set();
  const deduped = [];
  for (const h of [...sqlHits, ...domHits]) {
    if (seen.has(h.id)) continue;
    seen.add(h.id);
    deduped.push(h);
  }

  return deduped;
}

module.exports = {
  tokenizeSql,
  inspectSqlAst,
  inspectDomAst,
  inspectAst,
};
