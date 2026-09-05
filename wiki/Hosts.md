# `mlab-unifi hosts`

The consoles visible on a Site Manager account. Cloud mode only.

```bash
mlab-unifi -p cloud hosts
```

```
  Hosts

  NAME         TYPE     IP        ID
  udm.example  console  1.2.3.4   host-1
  uxg.example  console  5.6.7.8   host-2

  2 hosts
```

Route: `/v1/hosts`, cursor-paginated. mlab-unifi follows `nextToken` to the end
unless `--limit` asks for a single page.

Run against a local profile the command refuses rather than guessing:

```
  ✖ `hosts` is a cloud command; use --mode cloud or a cloud profile
```

A Site Manager key is not the same key as a console key: it comes from
`unifi.ui.com`, and a console key will be rejected. Keep them in two profiles.
