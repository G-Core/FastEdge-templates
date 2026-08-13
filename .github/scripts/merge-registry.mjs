#!/usr/bin/env node
// Deep-merges a template's registry.preprod.json onto its registry.json.
//
// Object keys merge recursively; a null value in the override deletes that
// key from the result. Arrays of objects with a `name` field (e.g. `params`)
// merge item-by-item by matching `name`: matching items merge recursively
// (so a param can have one field overridden/deleted without restating the
// whole param), override items with no match are appended, and base items
// with no override entry are kept as-is, in original order.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function mergeArraysByName(base, override) {
  const merged = base.map((item) => ({ ...item }));
  for (const overrideItem of override) {
    if (isPlainObject(overrideItem) && typeof overrideItem.name === 'string') {
      const i = merged.findIndex((item) => isPlainObject(item) && item.name === overrideItem.name);
      if (i !== -1) {
        merged[i] = deepMerge(merged[i], overrideItem);
        continue;
      }
    }
    merged.push(overrideItem);
  }
  return merged;
}

export function deepMerge(base, override) {
  if (Array.isArray(base) && Array.isArray(override)) {
    return mergeArraysByName(base, override);
  }
  if (isPlainObject(base) && isPlainObject(override)) {
    const result = { ...base };
    for (const [key, value] of Object.entries(override)) {
      if (value === null) {
        delete result[key];
      } else if (key in result) {
        result[key] = deepMerge(result[key], value);
      } else {
        result[key] = value;
      }
    }
    return result;
  }
  return override;
}

function main() {
  const templateDir = process.argv[2];
  if (!templateDir) {
    console.error('Usage: merge-registry.mjs <template_dir>');
    process.exit(1);
  }
  const base = JSON.parse(readFileSync(join(templateDir, 'registry.json'), 'utf8'));
  let override = {};
  try {
    override = JSON.parse(readFileSync(join(templateDir, 'registry.preprod.json'), 'utf8'));
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
  console.log(JSON.stringify(deepMerge(base, override)));
}

function selftest() {
  const assert = (cond, msg) => {
    if (!cond) throw new Error(`selftest failed: ${msg}`);
  };

  // plain key override
  assert(deepMerge({ a: 1, b: 2 }, { b: 3 }).b === 3, 'plain key override');

  // null deletes a key
  assert(!('a' in deepMerge({ a: 1, b: 2 }, { a: null })), 'null deletes a key');

  // params array: override existing, add new, keep untouched
  const base = {
    params: [
      { name: 'X', descr: 'old', metadata: '{}' },
      { name: 'Y', descr: 'keep' },
    ],
  };
  const override2 = {
    params: [
      { name: 'X', descr: 'new', metadata: null },
      { name: 'Z', descr: 'added' },
    ],
  };
  const merged = deepMerge(base, override2).params;
  assert(merged.length === 3, 'params array grows to 3');
  assert(merged[0].descr === 'new' && !('metadata' in merged[0]), 'X overridden, metadata deleted');
  assert(merged[1].descr === 'keep', 'Y untouched');
  assert(merged[2].descr === 'added', 'Z appended');

  // no override -> passthrough
  assert(deepMerge({ a: 1 }, {}).a === 1, 'empty override is a no-op');

  console.log('merge-registry selftest: all passed');
}

if (process.argv[2] === '--selftest') {
  selftest();
} else {
  main();
}
