# Admin SPA UI Restyle — Precision Ops (shadcn)

Date: 2026-09-21  
Status: approved (Approach 3)  
Direction: Precision ops · Neutral + amber · Compact

## Goals

- Replace the flat custom CSS shell with a shadcn/ui + Tailwind v4 kit
- Keep all existing routes and API behavior unchanged
- Feel like a dense instrument panel: hairline borders, monochrome chrome, amber only for focus/active/warn

## Stack

- Tailwind CSS v4 via `@tailwindcss/vite`
- shadcn/ui (Radix base) components owned under `web/src/components/ui`
- Fonts: Geist / Geist Mono (or Inter fallback if Geist CDN unavailable) — prefer system-adjacent geometric sans for density
- Icons: lucide-react (sparse — nav + status only)

## Theme tokens

- Background: near-black zinc (`oklch` neutrals)
- Foreground: high-contrast zinc-100
- Primary / ring / focus: amber-500 family
- Destructive / success / muted: semantic only (red / green / zinc)
- Radius: `0.375rem` (compact)
- Density: reduced padding on table rows, sidebar nav, form fields

## Surfaces

1. **Login** — centered card, brand mark, amber CTA, quiet ambient grid
2. **Shell** — narrow sidebar (~200px), hairline separators, amber active indicator
3. **Overview** — compact metric tiles + cluster strip + failures list
4. **Audit** — dense table + Sheet drawer for detail; live badge
5. **Secrets / Config / Runtime** — Card forms with Label/Input/Select/Checkbox; Alert for restart

## Non-goals

- Marketing landing aesthetics
- Purple/glow AI dashboard look
- Changing backend APIs
