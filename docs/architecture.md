# Secure FS Architecture

- Key Hierarchy: MK → KEK → CEK
- Storage: encrypted chunks in /storage
- Metadata: SQLite with encrypted filenames, ACLs
- Fuse Layer: read-only prototype first
