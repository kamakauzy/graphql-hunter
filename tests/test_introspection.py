import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from introspection import SchemaParser


class TestSchemaParserUploads(unittest.TestCase):
    def test_find_upload_targets_supports_nested_input_uploads(self):
        schema = {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [
                {
                    "kind": "OBJECT",
                    "name": "Mutation",
                    "fields": [
                        {
                            "name": "uploadAsset",
                            "args": [
                                {
                                    "name": "input",
                                    "type": {"kind": "NON_NULL", "ofType": {"kind": "INPUT_OBJECT", "name": "UploadAssetInput"}},
                                }
                            ],
                            "type": {"kind": "OBJECT", "name": "UploadAssetResult"},
                        }
                    ],
                },
                {
                    "kind": "INPUT_OBJECT",
                    "name": "UploadAssetInput",
                    "inputFields": [
                        {"name": "title", "type": {"kind": "SCALAR", "name": "String"}},
                        {"name": "file", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "Upload"}}},
                    ],
                },
                {
                    "kind": "OBJECT",
                    "name": "UploadAssetResult",
                    "fields": [{"name": "id", "args": [], "type": {"kind": "SCALAR", "name": "ID"}}],
                },
                {"kind": "SCALAR", "name": "String"},
                {"kind": "SCALAR", "name": "ID"},
                {"kind": "SCALAR", "name": "Upload"},
            ],
        }

        parser = SchemaParser(schema)
        mutation = parser.get_mutations()[0]
        targets = parser.find_upload_targets(mutation)

        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["variable_path"], "variables.input.file")


if __name__ == "__main__":
    unittest.main()
