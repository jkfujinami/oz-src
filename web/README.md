# OZ web

The static web version of OZ. The UI comes from `packages/ui`, shared with the desktop app.

```sh
npm run dev      # http://localhost:3000
npm run build    # static files in out/
```

Deploy `out/` to any static host. The maintainer key and Guard list in `../trust` are embedded at build time.
