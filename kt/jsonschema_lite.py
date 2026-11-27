"""A small, stdlib-only JSON Schema (draft 2020-12 subset) evaluator.

Supported keywords: $ref (local #/$defs only), type, enum, const, pattern,
minLength, maxLength, minimum, maximum, required, properties,
additionalProperties (bool or schema), items, minItems, maxItems,
uniqueItems, allOf, anyOf, oneOf, not, if/then/else.
Unknown keywords that affect validation raise, so the schema files can't
silently use something this evaluator ignores.

Patterns are anchored strictly: an unescaped `$` outside a character class is
evaluated as `\\Z`, so a trailing newline never satisfies a pattern (Python's `$`
also matches just before a final newline).
"""
import re

_IGNORED = {"$schema", "$id", "$comment", "title", "description", "$defs",
            "examples", "default", "format"}
_SUPPORTED = {"$ref", "type", "enum", "const", "pattern", "minLength",
              "maxLength", "minimum", "maximum", "required", "properties",
              "additionalProperties", "items", "minItems", "maxItems",
              "uniqueItems", "allOf", "anyOf", "oneOf", "not", "if", "then",
              "else"} | _IGNORED

_TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


class SchemaError(Exception):
    pass


_PATTERN_CACHE = {}
_SAFE_KEY = re.compile(r"[A-Za-z0-9_]{1,64}\Z")


def _strict(pattern):
    """Compile a schema pattern with every end-of-string `$` turned into `\\Z`."""
    c = _PATTERN_CACHE.get(pattern)
    if c is None:
        out, i, in_class = [], 0, False
        while i < len(pattern):
            ch = pattern[i]
            if ch == "\\" and i + 1 < len(pattern):
                out.append(pattern[i:i + 2])
                i += 2
                continue
            if in_class:
                if ch == "]":
                    in_class = False
            elif ch == "[":
                in_class = True
                if pattern[i + 1:i + 2] == "]":
                    out.append("[]")
                    i += 2
                    continue
            elif ch == "$":
                ch = "\\Z"
            out.append(ch)
            i += 1
        c = _PATTERN_CACHE[pattern] = re.compile("".join(out))
    return c


def _key_label(key):
    """Field names are echoed in errors only when they are plain identifiers (never attacker text)."""
    return key if isinstance(key, str) and _SAFE_KEY.match(key) else "<field>"


def _resolve(root, ref):
    if not ref.startswith("#/"):
        raise SchemaError("only local refs are supported: %s" % ref)
    node = root
    for part in ref[2:].split("/"):
        node = node[part]
    return node


def validate(instance, schema, root=None, path="$"):
    """Return a list of error strings (empty means valid)."""
    root = schema if root is None else root
    errors = []
    if schema is True:
        return errors
    if schema is False:
        return ["%s: not allowed" % path]
    unknown = set(schema) - _SUPPORTED
    if unknown:
        raise SchemaError("unsupported keywords at %s: %s" % (path, sorted(unknown)))
    if "$ref" in schema:
        errors += validate(instance, _resolve(root, schema["$ref"]), root, path)
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_TYPES[t](instance) for t in types):
            return errors + ["%s: expected type %s" % (path, "|".join(types))]
    if "enum" in schema and instance not in schema["enum"]:
        errors.append("%s: value not in enum" % path)
    if "const" in schema and instance != schema["const"]:
        errors.append("%s: value must be %r" % (path, schema["const"]))
    if isinstance(instance, str):
        if "pattern" in schema and not _strict(schema["pattern"]).search(instance):
            errors.append("%s: does not match pattern" % path)
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append("%s: too short" % path)
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append("%s: too long" % path)
    if _TYPES["number"](instance):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append("%s: below minimum" % path)
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append("%s: above maximum" % path)
    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                errors.append("%s: missing required field %s" % (path, key))
        props = schema.get("properties", {})
        addl = schema.get("additionalProperties", True)
        for key, val in instance.items():
            sub = "%s.%s" % (path, _key_label(key))
            if key in props:
                errors += validate(val, props[key], root, sub)
            elif addl is False:
                errors.append("%s: unexpected field" % sub)
            elif isinstance(addl, dict):
                errors += validate(val, addl, root, sub)
    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append("%s: too few items" % path)
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append("%s: too many items" % path)
        if schema.get("uniqueItems"):
            seen = []
            for item in instance:
                if item in seen:
                    errors.append("%s: duplicate items" % path)
                    break
                seen.append(item)
        if "items" in schema:
            for i, item in enumerate(instance):
                errors += validate(item, schema["items"], root, "%s[%d]" % (path, i))
    for sub in schema.get("allOf", []):
        errors += validate(instance, sub, root, path)
    if "anyOf" in schema:
        if not any(not validate(instance, s, root, path) for s in schema["anyOf"]):
            errors.append("%s: matches none of anyOf" % path)
    if "oneOf" in schema:
        n = sum(1 for s in schema["oneOf"] if not validate(instance, s, root, path))
        if n != 1:
            errors.append("%s: must match exactly one of oneOf (matched %d)" % (path, n))
    if "not" in schema and not validate(instance, schema["not"], root, path):
        errors.append("%s: matches a forbidden schema" % path)
    if "if" in schema:
        if not validate(instance, schema["if"], root, path):
            if "then" in schema:
                errors += validate(instance, schema["then"], root, path)
        elif "else" in schema:
            errors += validate(instance, schema["else"], root, path)
    return errors
