# `mlab-unifi sites`

List sites. Works in both modes, against different routes.

```bash
mlab-unifi sites
```

```
  Sites

  NAME     ID                                    REF
  Default  88f7af54-98f8-306a-a1c7-c9349722b1f6  default

  1 site
```

| Mode | Route |
| --- | --- |
| local | `/sites` on the [integration surface](Surfaces) |
| cloud | `/v1/sites` |

The `ID` column is what every other local command needs, and what `login`
stores in the profile. `REF` is the console's internal reference, which happens
to be the short name the [legacy and v2 surfaces](Surfaces) use for the same
site.

## Paging

Everything is fetched by default. `--limit` returns a single page of that size
instead, starting at `--offset`:

```bash
mlab-unifi sites --limit 10 --offset 20
```

Those two flags are shared by every list command.
