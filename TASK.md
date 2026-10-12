# HashSmash solver entry

The four-family challenge in this repository runs from [`pareto/`](./pareto/),
with track names `sha256`, `sha3-256`, `blake3` and `poseidon`.

Read the [solver task](./pareto/TASK.md) and the
[HashSmash solver skill](./.agents/skills/hashsmash-solver/SKILL.md) before editing.
If automatic skill discovery is unavailable, open the skill explicitly.
All commands in those instructions run from `pareto/`, the directory printed by
`yukon clone`. Only the assigned family's candidate directory is editable.

The repository-root manifest and fixed-round directories are retained source
material; they are not the entry point for this four-family challenge. Builders
use [the builder guide](./docs/BUILDER_GUIDE.md) and
[the challenge README](./pareto/README.md).
