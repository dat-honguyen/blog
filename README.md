# blog

Dat Ho's personal blog, at [blogs.datisa.dev](https://blogs.datisa.dev). Built with
[Astro](https://astro.build) on top of the [AstroPaper](https://github.com/satnaing/astro-paper)
theme.

Previously lived inside the `portfolio` repo as a `/blogs` subpath; split out into its own repo and
domain once self-hosting became available.

## Commands

All commands run from the repo root:

| Command          | Action                                                                                     |
| :--------------- | :------------------------------------------------------------------------------------------ |
| `pnpm install`   | Installs dependencies                                                                        |
| `pnpm dev`       | Starts local dev server at `localhost:4321`                                                  |
| `pnpm build`     | Type-checks, builds the site, runs Pagefind indexing, copies the index to `public/pagefind/` |
| `pnpm preview`   | Preview the build locally before deploying                                                   |
| `pnpm sync`      | Generates TypeScript types for Astro modules                                                 |
| `pnpm astro ...` | Run CLI commands like `astro add`, `astro check`                                             |

## Deployment

Deployed as a container on a self-hosted homelab box: `Dockerfile` builds the static site and
serves it via nginx, a self-hosted GitHub Actions runner builds/pushes the image on push to
`main`, and Podman Quadlet + Caddy + a Cloudflare Tunnel route it at blogs.datisa.dev. Full details
in `blog-homelab-runbook.md` in the homelab infra notes.

## Google Site Verification (optional)

Set `site.googleVerification` in `astro-paper.config.ts`:

```ts file="astro-paper.config.ts"
export default defineAstroPaperConfig({
    site: {
        // ...
        googleVerification: 'your-google-site-verification-value'
    }
    // ...
});
```

## License

Licensed under the MIT License. Built on the [AstroPaper](https://github.com/satnaing/astro-paper)
theme by [Sat Naing](https://satnaing.dev) — see `LICENSE`.
