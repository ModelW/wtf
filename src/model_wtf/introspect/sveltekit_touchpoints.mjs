// SvelteKit touchpoint introspection, executed *inside the unit* with the
// unit's own Node and TypeScript.
//
// model-wtf pipes this file to `node --input-type=module -` from the unit's
// folder after `svelte-kit sync` ran, so `.svelte-kit/types/src/routes/**/
// $types.d.ts` exists and `node_modules/typescript` is the project's
// compiler (types must be resolved with the same version the project uses).
// Plain Node, no dependency besides that: one JSON document on stdout.
//
// A route is a touchpoint. Id = the SvelteKit route ID (`/orders/[id]`).
// Facts: which files exist (+page.svelte, +page.server.ts, +server.ts,
// +layout*), HTTP handlers exported by +server, form actions, the shapes of
// `RouteParams`, `PageData` / `PageServerData` / `LayoutServerData` and
// `ActionData` flattened to `leaf: type` pairs, form field names found in
// the page markup, and the generated-API-client operations the route's code
// calls (`api.orders.checkout(` -> `checkout`), which link to the Django
// touchpoint by operation id. Raw `fetch("/back/api/...")` calls are kept as
// paths.
//
// Output schema (`schema: 1`):
//   {"schema": 1, "sveltekit": true, "touchpoints": [
//     {"id": "/kitchen/[restaurant_uuid]", "kind": "route",
//      "files": ["+page.svelte", "+page.server.ts"], "handlers": [],
//      "actions": ["default"], "params": ["restaurant_uuid"],
//      "data": {"whoami.email": "string", ...}, "action_data": {},
//      "form_fields": ["email", "message"],
//      "calls": ["whoami", "getRestaurant"], "fetches": ["/back/api/x"],
//      "file": "src/routes/kitchen/[restaurant_uuid]/+page.server.ts"}]}

import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const root = process.cwd();
const require = createRequire(path.join(root, "package.json"));
let ts;
try {
    ts = require("typescript");
} catch {
    process.stderr.write("model-wtf: typescript is not installed in this unit\n");
    process.exit(1);
}

const typesRoot = path.join(root, ".svelte-kit", "types", "src", "routes");
const routesRoot = path.join(root, "src", "routes");
if (!fs.existsSync(typesRoot)) {
    process.stderr.write(
        "model-wtf: .svelte-kit/types is missing; run `svelte-kit sync` first\n",
    );
    process.exit(1);
}

// ---------------------------------------------------------------------------
// TypeScript program over every generated $types.d.ts
// ---------------------------------------------------------------------------

function walk(dir, out = []) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full, out);
        else if (entry.name === "$types.d.ts") out.push(full);
    }
    return out;
}

const typeFiles = walk(typesRoot);
const configPath = ts.findConfigFile(root, ts.sys.fileExists, "tsconfig.json");
let compilerOptions = { strict: true, skipLibCheck: true };
if (configPath) {
    const parsed = ts.parseJsonConfigFileContent(
        ts.readConfigFile(configPath, ts.sys.readFile).config,
        ts.sys,
        path.dirname(configPath),
    );
    compilerOptions = { ...parsed.options, noEmit: true, skipLibCheck: true };
}
const program = ts.createProgram(typeFiles, compilerOptions);
const checker = program.getTypeChecker();

const MAX_LEAVES = 80;

function flatten(type, prefix, out, depth, seen) {
    if (Object.keys(out).length >= MAX_LEAVES || depth > 6) return out;
    const text = checker.typeToString(type);
    if (type.flags & ts.TypeFlags.Union) {
        const alts = type.types.filter(
            (t) => !(t.flags & (ts.TypeFlags.Undefined | ts.TypeFlags.Null | ts.TypeFlags.Void)),
        );
        if (alts.length === 1) return flatten(alts[0], prefix, out, depth, seen);
        if (alts.every((t) => t.flags & ts.TypeFlags.StringLiteral)) {
            out[prefix || "<value>"] = "string enum";
            return out;
        }
        if (alts.every((t) => !(t.flags & ts.TypeFlags.Object))) {
            out[prefix || "<value>"] = text;
            return out;
        }
        for (const alt of alts) flatten(alt, prefix, out, depth, seen);
        return out;
    }
    if (checker.isArrayType(type) || checker.isTupleType(type)) {
        const args = checker.getTypeArguments(type);
        return flatten(args[0] ?? checker.getAnyType(), `${prefix}[]`, out, depth + 1, seen);
    }
    if (type.flags & ts.TypeFlags.Object) {
        const symbolName = type.symbol?.name;
        const anonymous = !symbolName || ["__type", "__object"].includes(symbolName);
        if (!anonymous && seen.has(symbolName)) {
            out[prefix || symbolName] = `ref:${symbolName}`;
            return out;
        }
        // Runtime objects (Svelte components, DOM elements, classes with
        // methods) are not data: name them and stop.
        const isClassLike =
            type.symbol && (type.symbol.flags & ts.SymbolFlags.Class) !== 0;
        if (isClassLike || text === "Date" || /^(HTML|SVG)\w*Element$/.test(text)) {
            out[prefix || "<value>"] = text;
            return out;
        }
        if (checker.getSignaturesOfType(type, ts.SignatureKind.Call).length) {
            out[prefix || "<value>"] = "function";
            return out;
        }
        const nextSeen = anonymous ? seen : new Set([...seen, symbolName]);
        const props = checker.getPropertiesOfType(type);
        if (props.length === 0) {
            const index = checker.getIndexInfosOfType(type);
            out[prefix || "<object>"] = index.length ? "object(free-form)" : text;
            return out;
        }
        for (const prop of props) {
            const decl = prop.valueDeclaration ?? prop.declarations?.[0];
            const propType = decl
                ? checker.getTypeOfSymbolAtLocation(prop, decl)
                : checker.getTypeOfSymbol(prop);
            const name = prefix ? `${prefix}.${prop.name}` : prop.name;
            if (prop.flags & ts.SymbolFlags.Method) {
                out[name] = "function";
                continue;
            }
            flatten(propType, name, out, depth + 1, nextSeen);
        }
        return out;
    }
    out[prefix || "<value>"] = text;
    return out;
}

function exportedType(sourceFile, name) {
    const symbol = checker.getSymbolAtLocation(sourceFile);
    if (!symbol) return null;
    const exp = checker.getExportsOfModule(symbol).find((s) => s.name === name);
    if (!exp) return null;
    const decl = exp.declarations?.[0];
    if (!decl) return null;
    return checker.getTypeAtLocation(decl);
}

function shape(sourceFile, name) {
    const type = exportedType(sourceFile, name);
    if (!type) return {};
    const text = checker.typeToString(type);
    if (["unknown", "never", "void", "{}", "null", "undefined"].includes(text)) return {};
    return flatten(type, "", {}, 0, new Set());
}

function routeParams(sourceFile) {
    const type = exportedType(sourceFile, "RouteParams");
    if (!type) {
        // RouteParams is not exported in older kits; read it textually.
        const m = sourceFile.text.match(/type RouteParams = \{([^}]*)\}/);
        return m ? [...m[1].matchAll(/(\w+)\s*:/g)].map((x) => x[1]) : [];
    }
    return checker.getPropertiesOfType(type).map((p) => p.name);
}

// ---------------------------------------------------------------------------
// Source-level facts (files present, handlers, actions, forms, API calls)
// ---------------------------------------------------------------------------

const ROUTE_FILES = [
    "+page.svelte",
    "+page.ts",
    "+page.js",
    "+page.server.ts",
    "+page.server.js",
    "+server.ts",
    "+server.js",
    "+layout.svelte",
    "+layout.ts",
    "+layout.js",
    "+layout.server.ts",
    "+layout.server.js",
];
const HANDLER = /export\s+(?:const|async\s+function|function)\s+(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|fallback)\b/g;
const API_CALL = /\bapi\.(\w+)\.(\w+)\s*\(/g;
const RAW_FETCH = /fetch\(\s*[`'"]([^`'"]*\/(?:api|back)\/[^`'"?]*)/g;
const FORM_FIELD = /\bname\s*=\s*["']([\w.\-\[\]]+)["']/g;
const FORM_DATA_GET = /formData\.get\(\s*["']([\w.\-\[\]]+)["']/g;

function actionsOf(text) {
    const m = text.match(/export\s+const\s+actions\s*(?::\s*Actions)?\s*=\s*\{([\s\S]*?)\n\}/);
    if (!m) return text.includes("export const actions") ? ["?"] : [];
    return [...m[1].matchAll(/^\s{4}(?:async\s+)?(\w+)\s*[:(]/gm)].map((x) => x[1]);
}

function matches(text, re) {
    return [...new Set([...text.matchAll(re)].map((m) => m[1]))];
}

function apiCalls(text) {
    return [...new Set([...text.matchAll(API_CALL)].map((m) => m[2]))];
}

const touchpoints = [];
for (const typeFile of typeFiles) {
    const rel = path.relative(typesRoot, path.dirname(typeFile));
    const routeId = "/" + rel.split(path.sep).join("/").replace(/^\.$/, "");
    const routeDir = path.join(routesRoot, rel);
    const files = ROUTE_FILES.filter((f) => fs.existsSync(path.join(routeDir, f)));
    if (files.length === 0) continue;
    const sourceFile = program.getSourceFile(typeFile);

    let handlers = [];
    let actions = [];
    const calls = new Set();
    const fetches = new Set();
    const formFields = new Set();
    for (const f of files) {
        const text = fs.readFileSync(path.join(routeDir, f), "utf8");
        if (f.startsWith("+server")) handlers = matches(text, HANDLER);
        if (f.startsWith("+page.server")) actions = actionsOf(text);
        for (const c of apiCalls(text)) calls.add(c);
        for (const u of matches(text, RAW_FETCH)) fetches.add(u);
        if (f.endsWith(".svelte")) {
            for (const n of matches(text, FORM_FIELD)) formFields.add(n);
        }
        for (const n of matches(text, FORM_DATA_GET)) formFields.add(n);
    }

    const isLayoutOnly = files.every((f) => f.startsWith("+layout"));
    const dataName = isLayoutOnly ? "LayoutData" : "PageData";
    const main =
        files.find((f) => f.startsWith("+page.server")) ??
        files.find((f) => f.startsWith("+server")) ??
        files.find((f) => f.startsWith("+page")) ??
        files[0];
    touchpoints.push({
        id: routeId === "/" ? "/" : routeId,
        kind: "route",
        layout_only: isLayoutOnly,
        files,
        handlers,
        actions,
        params: sourceFile ? routeParams(sourceFile) : [],
        data: sourceFile ? shape(sourceFile, dataName) : {},
        action_data: sourceFile ? shape(sourceFile, "ActionData") : {},
        form_fields: [...formFields].sort(),
        calls: [...calls].sort(),
        fetches: [...fetches].sort(),
        file: path.relative(root, path.join(routeDir, main)).split(path.sep).join("/"),
    });
}

process.stdout.write(
    JSON.stringify({ schema: 1, sveltekit: true, touchpoints }) + "\n",
);
