import unittest

from kt.jsonschema_lite import SchemaError, validate


class TestLite(unittest.TestCase):
    def test_basic_keywords(self):
        s = {"type": "object", "additionalProperties": False, "required": ["a"],
             "properties": {"a": {"type": "string", "pattern": "^x+$", "maxLength": 3},
                            "b": {"type": "array", "items": {"enum": [1, 2]}, "uniqueItems": True, "maxItems": 2}}}
        self.assertEqual(validate({"a": "xx"}, s), [])
        self.assertTrue(validate({"a": "xy"}, s))
        self.assertTrue(validate({"a": "xxxx"}, s))
        self.assertTrue(validate({}, s))
        self.assertTrue(validate({"a": "x", "c": 1}, s))
        self.assertTrue(validate({"a": "x", "b": [1, 1]}, s))
        self.assertTrue(validate({"a": "x", "b": [3]}, s))

    def test_bool_is_not_integer(self):
        self.assertTrue(validate(True, {"type": "integer"}))

    def test_if_then_else_and_ref(self):
        s = {"$defs": {"n": {"type": "null"}}, "if": {"properties": {"m": {"const": 1}}},
             "then": {"required": ["x"]}, "else": {"properties": {"x": {"$ref": "#/$defs/n"}}}}
        self.assertEqual(validate({"m": 1, "x": 5}, s), [])
        self.assertTrue(validate({"m": 1}, s))
        self.assertTrue(validate({"m": 2, "x": 5}, s))

    def test_unknown_keyword_raises(self):
        with self.assertRaises(SchemaError):
            validate(1, {"multipleOf": 2})
