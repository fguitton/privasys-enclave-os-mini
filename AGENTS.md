# Repository instructions

## Pre-MVP: one current implementation, no backward compatibility

- Until MVP is explicitly declared, maintain one current representation and one
  accepted format for each conceptual object, protocol and execution profile.
  A successor replaces its predecessor; it does not add another supported level.
- Remove superseded objects, implementations, decoders, wire branches, profile
  selectors, feature flags, adapters, aliases, wrappers, fallback paths and glue.
  Do not preserve an old generation for existing fixtures, historical snapshots,
  stored test data, external callers or convenience. Update the current callers
  and regenerate fixtures together. Git history retains historical source.
- Preserve required product capabilities by expressing them directly in the
  current model. Move genuinely shared behavior into a single current primitive;
  do not keep predecessor types, conversion layers or compatibility constructors
  merely because the successor currently depends on them.
- Qualify the current path and rejection of unsupported formats. Remove obsolete
  positive compatibility tests and matrix rows, and reconcile discovery, counts,
  source guards, configuration and documentation in the same change.
- Do not mistake an isolated version suffix, a generation counter, distinct
  domain concepts, third-party standards interoperability or rejection of legacy
  input for a requirement to support multiple internal generations. Trace the
  actual producers, consumers and selectable paths before deleting code.
- Do not introduce compatibility code without a new explicit user instruction.
  Lint repair is not a reason to retain or repair a superseded implementation.

