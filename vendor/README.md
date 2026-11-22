# Local dependency patches

The source in each directory is from the corresponding published crate. Each crate's licenses
are included next to its manifest.

- SeaORM 2.0.4 drops the weak Arrow feature edge from `with-time`. Cargo otherwise records
  Arrow and its mandatory Chrono dependency in this application's lockfile even with Arrow
  inactive. Imports used only by disabled features are gated to keep the build warning-free.
- Croner 5.0.0 drops the weak Chrono feature edge from `std`. Cargo otherwise records the
  unused backend in the application's lockfile.

Recheck the upstream feature graphs when updating either dependency and remove each local
patch when the lockfile can resolve without it.
