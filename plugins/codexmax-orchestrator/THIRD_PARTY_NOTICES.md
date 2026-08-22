# Codexmax Third-Party And Runtime Inventory

This file is an engineering inventory, not legal advice and not a legal or
compliance conclusion. It records source-visible runtime and integration
boundaries for the local Codexmax candidate.

## Bundled Product Source

The installable product surface is `plugins/codexmax-orchestrator/`. Static
Python import inspection finds only Python standard-library modules in its
scripts. The product tree does not vendor a third-party Python package or
JavaScript package.

## Runtime And Integration Boundaries

| Boundary | Relationship | Bundled | Source evidence | License evidence in this repository |
| --- | --- | --- | --- | --- |
| Python 3.11 or newer | Runtime interpreter and standard library | No | Root `package.json` engine declaration and plugin Python imports | No copied Python license text; operator/runtime distribution owns its notices |
| Codex/ChatGPT host | Loads the plugin manifest and skills | No | `.codex-plugin/plugin.json` | No host license text copied into this plugin |
| GoalBuddy | Separately versioned canonical board and UI | No | WorkGraph GoalBuddy adapter contract and release goal boundary | External repository license is not inferred here |

The root `package.json` declares no `dependencies`, `devDependencies`,
`optionalDependencies`, or `peerDependencies`. Repository validators may use
software supplied by the host workspace, but that does not make it bundled
plugin runtime content.

## Review Boundary

The deterministic trust report inventories current product files, Python
imports, root dependency declarations, and this notice. A later packaging or
distribution checkpoint must repeat the inventory against the immutable
release manifest and add any notices required by the actual distributed
payload. Absence from this source-visible inventory is not a legal permission
or prohibition.
