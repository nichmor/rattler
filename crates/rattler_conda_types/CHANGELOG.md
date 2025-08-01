# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.35.6](https://github.com/conda/rattler/compare/rattler_conda_types-v0.35.5...rattler_conda_types-v0.35.6) - 2025-07-14

### Fixed

- *(clobber registry)* directory and file clobbering ([#1497](https://github.com/conda/rattler/pull/1497))

## [0.35.5](https://github.com/conda/rattler/compare/rattler_conda_types-v0.35.4...rattler_conda_types-v0.35.5) - 2025-07-09

### Other

- move upload from `rattler-build` to `rattler` ([#1386](https://github.com/conda/rattler/pull/1386))

## [0.35.4](https://github.com/conda/rattler/compare/rattler_conda_types-v0.35.3...rattler_conda_types-v0.35.4) - 2025-07-01

### Fixed

- *(ci)* run pre-commit-run for all files ([#1481](https://github.com/conda/rattler/pull/1481))
- use kebab-case ([#1482](https://github.com/conda/rattler/pull/1482))

## [0.35.3](https://github.com/conda/rattler/compare/rattler_conda_types-v0.35.2...rattler_conda_types-v0.35.3) - 2025-06-26

### Fixed

- allow track_features to be patched to null ([#1477](https://github.com/conda/rattler/pull/1477))

## [0.35.2](https://github.com/conda/rattler/compare/rattler_conda_types-v0.35.1...rattler_conda_types-v0.35.2) - 2025-06-25

### Other

- *(ci)* Update Rust crate criterion to 0.6 ([#1438](https://github.com/conda/rattler/pull/1438))

## [0.35.1](https://github.com/conda/rattler/compare/rattler_conda_types-v0.35.0...rattler_conda_types-v0.35.1) - 2025-06-23

### Added

- add `rattler_config` crate (derived from `pixi_config`) ([#1389](https://github.com/conda/rattler/pull/1389))

### Fixed

- fix code to use nom 8
- parsing of `=0.*,>=0.4.1` ([#1384](https://github.com/conda/rattler/pull/1384))

### Other

- *(ci)* Update Rust crate nom to v8 ([#1404](https://github.com/conda/rattler/pull/1404))
- Revert "fix code to use nom 8"
- update npm name ([#1368](https://github.com/conda/rattler/pull/1368))
- update readme ([#1364](https://github.com/conda/rattler/pull/1364))

## [0.35.0](https://github.com/conda/rattler/compare/rattler_conda_types-v0.34.0...rattler_conda_types-v0.35.0) - 2025-05-23

### Added

- Sharded repodata, zst, add purls and run_exports support ([#1312](https://github.com/conda/rattler/pull/1312))
- control over selection of .conda and .tar.bz2 ([#1344](https://github.com/conda/rattler/pull/1344))

### Fixed

- *(py)* package count was incorrect for prefer-conda ([#1350](https://github.com/conda/rattler/pull/1350))
- add missing `created_at` in shards ([#1343](https://github.com/conda/rattler/pull/1343))
- properly dedup package names ([#1342](https://github.com/conda/rattler/pull/1342))

## [0.34.0](https://github.com/conda/rattler/compare/rattler_conda_types-v0.33.0...rattler_conda_types-v0.34.0) - 2025-05-16

### Added

- add purls to `IndexJson` ([#1303](https://github.com/conda/rattler/pull/1303))

### Fixed

- skip serializing if purls are None ([#1306](https://github.com/conda/rattler/pull/1306))

### Other

- make sure that md5 also works as `CacheKey` ([#1293](https://github.com/conda/rattler/pull/1293))
- Bump zip to 3.0.0 ([#1310](https://github.com/conda/rattler/pull/1310))

## [0.33.0](https://github.com/conda/rattler/compare/rattler_conda_types-v0.32.0...rattler_conda_types-v0.33.0) - 2025-05-03

### Added

- add `history` file to conda-meta folder ([#1289](https://github.com/conda/rattler/pull/1289))

### Fixed

- menuinst windows shortcut path ([#1273](https://github.com/conda/rattler/pull/1273))

### Other

- lock workspace member dependencies ([#1279](https://github.com/conda/rattler/pull/1279))

## [0.32.0](https://github.com/conda/rattler/compare/rattler_conda_types-v0.31.6...rattler_conda_types-v0.32.0) - 2025-04-10

### Added

- Add license to MatchSpec ([#1236](https://github.com/conda/rattler/pull/1236))

### Fixed

- MatchSpec matches if license is set ([#1247](https://github.com/conda/rattler/pull/1247))
- add support for `asterisk (*)` in package names for `MatchSpec` ([#1245](https://github.com/conda/rattler/pull/1245))

## [0.31.6](https://github.com/conda/rattler/compare/rattler_conda_types-v0.31.5...rattler_conda_types-v0.31.6) - 2025-04-04

### Fixed

- allow empty info key in repodata.json ([#1181](https://github.com/conda/rattler/pull/1181))

### Other

- add the remove_from_backup function and update the prefix ([#1155](https://github.com/conda/rattler/pull/1155))

## [0.31.5](https://github.com/conda/rattler/compare/rattler_conda_types-v0.31.4...rattler_conda_types-v0.31.5) - 2025-03-14

### Added

- package record ([#1148](https://github.com/conda/rattler/pull/1148))

## [0.31.4](https://github.com/conda/rattler/compare/rattler_conda_types-v0.31.3...rattler_conda_types-v0.31.4) - 2025-03-10

### Added

- Add support for repodata patching in rattler-index, fix silent failures ([#1129](https://github.com/conda/rattler/pull/1129))

## [0.31.3](https://github.com/conda/rattler/compare/rattler_conda_types-v0.31.2...rattler_conda_types-v0.31.3) - 2025-03-04

### Other

- updated the following local packages: rattler_redaction

## [0.31.2](https://github.com/conda/rattler/compare/rattler_conda_types-v0.31.1...rattler_conda_types-v0.31.2) - 2025-02-28

### Fixed

- roundtrip of arch/platform in lock files (#1124)

## [0.31.1](https://github.com/conda/rattler/compare/rattler_conda_types-v0.31.0...rattler_conda_types-v0.31.1) - 2025-02-27

### Added

- Use `opendal` in `rattler-index` and add executable (#1076)

## [0.31.0](https://github.com/conda/rattler/compare/rattler_conda_types-v0.30.3...rattler_conda_types-v0.31.0) - 2025-02-25

### Added

- add `rattler_menuinst` crate (#840)
- initial wasm/ts/js bindings (#1079)

## [0.30.3](https://github.com/conda/rattler/compare/rattler_conda_types-v0.30.2...rattler_conda_types-v0.30.3) - 2025-02-18

### Added

- write prefix record atomically (#1063)

### Other

- update dependencies (#1069)

## [0.30.2](https://github.com/conda/rattler/compare/rattler_conda_types-v0.30.1...rattler_conda_types-v0.30.2) - 2025-02-06

### Other

- bump rust 1.84.1 (#1053)

## [0.30.1](https://github.com/conda/rattler/compare/rattler_conda_types-v0.30.0...rattler_conda_types-v0.30.1) - 2025-02-03

### Fixed

- track feature serialization and deserialization (#1039)

## [0.30.0](https://github.com/conda/rattler/compare/rattler_conda_types-v0.29.10...rattler_conda_types-v0.30.0) - 2025-01-23

### Added

- add linux-ppc (PPC32 BE) platform to rattler (#1024)

## [0.29.10](https://github.com/conda/rattler/compare/rattler_conda_types-v0.29.9...rattler_conda_types-v0.29.10) - 2025-01-09

### Added

- Match GenericVirtualPackage with MatchSpec (#1016)

## [0.29.9](https://github.com/conda/rattler/compare/rattler_conda_types-v0.29.8...rattler_conda_types-v0.29.9) - 2025-01-09

### Added

- expose ParseConstraintError (#1020)

## [0.29.8](https://github.com/conda/rattler/compare/rattler_conda_types-v0.29.7...rattler_conda_types-v0.29.8) - 2025-01-08

### Added

- add deserialize from string for types (#1015)
- require a range specifier for version spec in strict mode (#989)

### Fixed

- parsing of >=2.*.* (#1006)

## [0.29.7](https://github.com/conda/rattler/compare/rattler_conda_types-v0.29.6...rattler_conda_types-v0.29.7) - 2024-12-20

### Other

- reflink directories at once on macOS (#995)
- read json to memory before parsing (#991)

## [0.29.6](https://github.com/conda/rattler/compare/rattler_conda_types-v0.29.5...rattler_conda_types-v0.29.6) - 2024-12-17

### Added

- speed up `PrefixRecord` loading (#984)

## [0.29.5](https://github.com/conda/rattler/compare/rattler_conda_types-v0.29.4...rattler_conda_types-v0.29.5) - 2024-12-13

### Added

- derive `PartialEq` and `Eq` for `ChannelConfig` (#982)

## [0.29.4](https://github.com/conda/rattler/compare/rattler_conda_types-v0.29.3...rattler_conda_types-v0.29.4) - 2024-12-12

### Added
- add `EnumIter` to `Arch` ([#972](https://github.com/conda/rattler/pull/972))

## [0.29.3](https://github.com/conda/rattler/compare/rattler_conda_types-v0.29.2...rattler_conda_types-v0.29.3) - 2024-11-30

### Added

- merge pixi-build branch ([#950](https://github.com/conda/rattler/pull/950))

### Fixed

- `pixi project version` doesn't reset minor and patch version numbers ([#954](https://github.com/conda/rattler/pull/954))

## [0.29.2](https://github.com/conda/rattler/compare/rattler_conda_types-v0.29.1...rattler_conda_types-v0.29.2) - 2024-11-18

### Added

- channel is serialized without trailing slash ([#948](https://github.com/conda/rattler/pull/948))

### Other

- allow `ChannelUrl` in `Channel::from_url` interface ([#944](https://github.com/conda/rattler/pull/944))

## [0.29.1](https://github.com/conda/rattler/compare/rattler_conda_types-v0.29.0...rattler_conda_types-v0.29.1) - 2024-11-14

### Other

- enable using sharded repodata for custom channels ([#910](https://github.com/conda/rattler/pull/910))

## [0.29.0](https://github.com/conda/rattler/compare/rattler_conda_types-v0.28.3...rattler_conda_types-v0.29.0) - 2024-11-04

### Added

- use python_site_packages_path field when available for installing noarch: python packages, CEP-17 ([#909](https://github.com/conda/rattler/pull/909))
- Add `PackageRecord::validate` function ([#911](https://github.com/conda/rattler/pull/911))

### Fixed

- matchspec build / version from brackets and string serialization ([#917](https://github.com/conda/rattler/pull/917))

### Other

- root constraint shouldnt crash ([#916](https://github.com/conda/rattler/pull/916))

## [0.28.3](https://github.com/conda/rattler/compare/rattler_conda_types-v0.28.2...rattler_conda_types-v0.28.3) - 2024-10-21

### Other

- updated the following local packages: file_url

## [0.28.2](https://github.com/conda/rattler/compare/rattler_conda_types-v0.28.1...rattler_conda_types-v0.28.2) - 2024-10-07

### Other

- add snapshot tests to verify solver sorting order ([#895](https://github.com/conda/rattler/pull/895))

## [0.28.1](https://github.com/conda/rattler/compare/rattler_conda_types-v0.28.0...rattler_conda_types-v0.28.1) - 2024-10-03

### Fixed

- topological sort when cycles appear in leaf nodes ([#879](https://github.com/conda/rattler/pull/879))

## [0.28.0](https://github.com/conda/rattler/compare/rattler_conda_types-v0.27.6...rattler_conda_types-v0.28.0) - 2024-09-23

### Added

- add path to namedchannelorurl ([#873](https://github.com/conda/rattler/pull/873))
- add serialization for `GenericVirtualPackage` ([#865](https://github.com/conda/rattler/pull/865))

### Fixed

- improve when we print brackets ([#861](https://github.com/conda/rattler/pull/861))

## [0.27.6](https://github.com/conda/rattler/compare/rattler_conda_types-v0.27.5...rattler_conda_types-v0.27.6) - 2024-09-09

### Fixed

- publish `MatchSpecOrSubSection` for env yaml ([#855](https://github.com/conda/rattler/pull/855))

## [0.27.5](https://github.com/conda/rattler/compare/rattler_conda_types-v0.27.4...rattler_conda_types-v0.27.5) - 2024-09-05

### Fixed
- typos ([#849](https://github.com/conda/rattler/pull/849))

## [0.27.4](https://github.com/conda/rattler/compare/rattler_conda_types-v0.27.3...rattler_conda_types-v0.27.4) - 2024-09-03

### Other
- make PackageCache multi-process safe ([#837](https://github.com/conda/rattler/pull/837))

## [0.27.3](https://github.com/conda/rattler/compare/rattler_conda_types-v0.27.2...rattler_conda_types-v0.27.3) - 2024-09-02

### Added
- add edge case tests for `StringMatcher` ([#839](https://github.com/conda/rattler/pull/839))

## [0.27.2](https://github.com/conda/rattler/compare/rattler_conda_types-v0.27.1...rattler_conda_types-v0.27.2) - 2024-08-15

### Added
- add extra field ([#811](https://github.com/conda/rattler/pull/811))
- parse `channel` key and consolidate `NamelessMatchSpec` ([#810](https://github.com/conda/rattler/pull/810))

### Fixed
- move more links to the conda org from conda-incubator ([#816](https://github.com/conda/rattler/pull/816))
- use conda-incubator

### Other
- change links from conda-incubator to conda ([#813](https://github.com/conda/rattler/pull/813))
- update banner ([#808](https://github.com/conda/rattler/pull/808))

## [0.27.1](https://github.com/baszalmstra/rattler/compare/rattler_conda_types-v0.27.0...rattler_conda_types-v0.27.1) - 2024-08-06

### Fixed
- parse `~=` as version not as path ([#804](https://github.com/baszalmstra/rattler/pull/804))

## [0.27.0](https://github.com/baszalmstra/rattler/compare/rattler_conda_types-v0.26.3...rattler_conda_types-v0.27.0) - 2024-08-02

### Fixed
- redact secrets in the `canonical_name` functions ([#801](https://github.com/baszalmstra/rattler/pull/801))
- make `base_url` of `Channel` always contain a trailing slash ([#800](https://github.com/baszalmstra/rattler/pull/800))
- parse channel in matchspec string ([#792](https://github.com/baszalmstra/rattler/pull/792))
- constraints on virtual packages were ignored ([#795](https://github.com/baszalmstra/rattler/pull/795))
- url parsing for namelessmatchspec and cleanup functions ([#790](https://github.com/baszalmstra/rattler/pull/790))

### Other
- mark some crates 1.0 ([#789](https://github.com/baszalmstra/rattler/pull/789))

## [0.26.3](https://github.com/conda/rattler/compare/rattler_conda_types-v0.26.2...rattler_conda_types-v0.26.3) - 2024-07-23

### Fixed
- channel `base_url` requires trailing slash ([#787](https://github.com/conda/rattler/pull/787))

## [0.26.2](https://github.com/conda/rattler/compare/rattler_conda_types-v0.26.1...rattler_conda_types-v0.26.2) - 2024-07-23

### Added
- `environment.yaml` type ([#786](https://github.com/conda/rattler/pull/786))
- Add to_path() method to ExplicitEnvironmentSpec ([#781](https://github.com/conda/rattler/pull/781))
- expose `HasPrefixEntry` for public use ([#784](https://github.com/conda/rattler/pull/784))

## [0.26.1](https://github.com/conda/rattler/compare/rattler_conda_types-v0.26.0...rattler_conda_types-v0.26.1) - 2024-07-15

### Other
- PrefixRecord deserialization using simd ([#777](https://github.com/conda/rattler/pull/777))

## [0.26.0](https://github.com/conda/rattler/compare/rattler_conda_types-v0.25.2...rattler_conda_types-v0.26.0) - 2024-07-08

### Added
- add support for zos-z ([#753](https://github.com/conda/rattler/pull/753))
- return pybytes for sha256 and md5 everywhere and use md5 hash for legacy bz2 md5 ([#752](https://github.com/conda/rattler/pull/752))
- add direct url repodata building ([#725](https://github.com/conda/rattler/pull/725))
- add shards_base_url and write shards atomically ([#747](https://github.com/conda/rattler/pull/747))

### Fixed
- allow version following package in strict mode ([#770](https://github.com/conda/rattler/pull/770))
- Fix doctests and start testing them again ([#767](https://github.com/conda/rattler/pull/767))
- skip over implicit `0` components when copying ([#760](https://github.com/conda/rattler/pull/760))
- allow empty json repodata ([#745](https://github.com/conda/rattler/pull/745))
- lenient and strict parsing of equality signs ([#738](https://github.com/conda/rattler/pull/738))
- This fixes parsing of `ray[default,data] >=2.9.0,<3.0.0` ([#732](https://github.com/conda/rattler/pull/732))

## [0.25.2](https://github.com/baszalmstra/rattler/compare/rattler_conda_types-v0.25.1...rattler_conda_types-v0.25.2) - 2024-06-04

### Added
- parse url and path as matchspec ([#704](https://github.com/baszalmstra/rattler/pull/704))

### Fixed
- issue 722 ([#723](https://github.com/baszalmstra/rattler/pull/723))

### Other
- remove lfs ([#512](https://github.com/baszalmstra/rattler/pull/512))
- move the cache tooling into its own crate for reuse downstream ([#721](https://github.com/baszalmstra/rattler/pull/721))

## [0.25.1](https://github.com/conda/rattler/compare/rattler_conda_types-v0.25.0...rattler_conda_types-v0.25.1) - 2024-06-03

### Added
- add a `with_alpha` function that adds `0a0` to the version ([#696](https://github.com/conda/rattler/pull/696))

## [0.25.0](https://github.com/conda/rattler/compare/rattler_conda_types-v0.24.0...rattler_conda_types-v0.25.0) - 2024-05-28

### Added
- when bumping, extend versions with `0` to match the bump request ([#695](https://github.com/conda/rattler/pull/695))
- extend tests and handle characters better when bumping versions ([#694](https://github.com/conda/rattler/pull/694))
- add a function to extend version with `0s` ([#689](https://github.com/conda/rattler/pull/689))
- add run exports to package data ([#671](https://github.com/conda/rattler/pull/671))

### Fixed
- lenient parsing of 2023.*.* ([#688](https://github.com/conda/rattler/pull/688))
- VersionSpec starts with, with trailing zeros ([#686](https://github.com/conda/rattler/pull/686))

### Other
- move bump implementation to bump.rs and simplify tests ([#692](https://github.com/conda/rattler/pull/692))

## [0.24.0](https://github.com/conda/rattler/compare/rattler_conda_types-v0.23.1...rattler_conda_types-v0.24.0) - 2024-05-27

### Added
- removed Ord and more ([#673](https://github.com/conda/rattler/pull/673))
- always store purls as a key in lock file ([#669](https://github.com/conda/rattler/pull/669))
- add solve strategies ([#660](https://github.com/conda/rattler/pull/660))

### Fixed
- make topological sorting support fully cyclic dependencies ([#678](https://github.com/conda/rattler/pull/678))

## [0.23.1](https://github.com/conda/rattler/compare/rattler_conda_types-v0.23.0...rattler_conda_types-v0.23.1) - 2024-05-14

### Added
- exclude repodata records based on timestamp ([#654](https://github.com/conda/rattler/pull/654))

## [0.23.0](https://github.com/conda/rattler/compare/rattler_conda_types-v0.22.1...rattler_conda_types-v0.23.0) - 2024-05-13

### Added
- high level repodata access ([#560](https://github.com/conda/rattler/pull/560))

### Other
- update README.md

## [0.22.1](https://github.com/conda/rattler/compare/rattler_conda_types-v0.22.0...rattler_conda_types-v0.22.1) - 2024-05-06

### Added
- expose `*Record.noarch` in Python bindings ([#635](https://github.com/conda/rattler/pull/635))

## [0.22.0](https://github.com/conda/rattler/compare/rattler_conda_types-v0.21.0...rattler_conda_types-v0.22.0) - 2024-04-25

### Added
- add support for extracting prefix placeholder data to PathsEntry ([#614](https://github.com/conda/rattler/pull/614))

## [0.21.0](https://github.com/conda/rattler/compare/rattler_conda_types-v0.20.5...rattler_conda_types-v0.21.0) - 2024-04-19

### Added
- make root dir configurable in channel config ([#602](https://github.com/conda/rattler/pull/602))

### Fixed
- better value for `link` field ([#610](https://github.com/conda/rattler/pull/610))

### Other
- update dependencies incl. reqwest ([#606](https://github.com/conda/rattler/pull/606))

## [0.20.5](https://github.com/baszalmstra/rattler/compare/rattler_conda_types-v0.20.4...rattler_conda_types-v0.20.5) - 2024-04-05

### Fixed
- run post-link scripts ([#574](https://github.com/baszalmstra/rattler/pull/574))

## [0.20.4](https://github.com/conda/rattler/compare/rattler_conda_types-v0.20.3...rattler_conda_types-v0.20.4) - 2024-03-30

### Fixed
- matchspec empty namespace and channel canonical name ([#582](https://github.com/conda/rattler/pull/582))

## [0.20.3](https://github.com/conda/rattler/compare/rattler_conda_types-v0.20.2...rattler_conda_types-v0.20.3) - 2024-03-21

### Fixed
- allow not starts with in strict mode ([#577](https://github.com/conda/rattler/pull/577))

## [0.20.2](https://github.com/conda/rattler/compare/rattler_conda_types-v0.20.1...rattler_conda_types-v0.20.2) - 2024-03-14

### Other
- add pixi badge ([#563](https://github.com/conda/rattler/pull/563))

## [0.20.1](https://github.com/conda/rattler/compare/rattler_conda_types-v0.20.0...rattler_conda_types-v0.20.1) - 2024-03-08

### Fixed
- chrono deprecation warnings ([#558](https://github.com/conda/rattler/pull/558))

## [0.20.0](https://github.com/conda/rattler/compare/rattler_conda_types-v0.19.0...rattler_conda_types-v0.20.0) - 2024-03-06

### Added
- [**breaking**] optional strict parsing of matchspec and versionspec ([#552](https://github.com/conda/rattler/pull/552))

### Fixed
- patch unsupported glob operators ([#551](https://github.com/conda/rattler/pull/551))
- dont use workspace dependencies for local crates ([#546](https://github.com/conda/rattler/pull/546))

### Other
- every crate should have its own version ([#557](https://github.com/conda/rattler/pull/557))

## [0.19.0](https://github.com/baszalmstra/rattler/compare/rattler_conda_types-v0.18.0...rattler_conda_types-v0.19.0) - 2024-02-26

### Fixed
- Fix arch for osx-arm64 and win-arm64 ([#528](https://github.com/baszalmstra/rattler/pull/528))
- Channel name display ([#531](https://github.com/baszalmstra/rattler/pull/531))
