# SQLite archive integrity

The helper accepts these exact upstream archives. Every download, including a
fallback URL, must match its pinned SHA-256 before entering the cache. Cached
archives are checked again before extraction. Each build extracts into a fresh
private directory and removes that directory on exit; an existing source cache
is never compiled.

| SQLite | Official archive | Archive SHA-256 |
| --- | --- | --- |
| 3.46.0 | <https://www.sqlite.org/2024/sqlite-amalgamation-3460000.zip> | `712a7d09d2a22652fb06a49af516e051979a3984adb067da86760e60ed51a7f5` |
| 3.25.0 | <https://www.sqlite.org/2018/sqlite-amalgamation-3250000.zip> | `8eac27252908500ba65c6558d98a252024147209756418f98dd83c746877d9cf` |

These archive hashes were calculated from the official downloads on 22 November
2026. The existing fallback downloads were byte-identical. The extracted
`sqlite3.c` files were separately checked against SQLite's published SHA3-256:

- [3.46.0 release](https://www.sqlite.org/releaselog/3_46_0.html):
  `094429ea827fcd32275e767134bc6c7b9ea394a2c5a9e653dd0a0690b2c11358`.
- [3.25.0 release](https://www.sqlite.org/releaselog/3_25_0.html):
  `989e3ff37f2b5eea8e42205f808ccf0ba86c6ea6aa928ad2c011f33a108ac45d`.

When adding a version, verify its official archive and published source digest
before adding its pin. A failed cached-archive check stops the build; remove the
invalid archive or its Actions cache before retrying. The helper supports
`sha256sum` and macOS's `shasum -a 256` and fails if neither is available.

Run the isolated helper regression tests without network access or compilation:

```sh
python tests/test_setup_sqlite_version.py
```
