# Fixture for I8: a module that needs a host built-in (sprintf). The JS SDK
# implements sprintf in JavaScript, Python does not. Both runtimes must refuse
# to load it, otherwise browser and backend could silently disagree.
# Rebuild: opa build -t wasm -e paylineage/decision needs_builtin.rego
package paylineage

import rego.v1

decision := {"decision": "allow", "reasons": [], "policy_version": sprintf("%d", [1])}
