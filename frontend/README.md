# CyberSentry V1 — Frontend Scaffold

AI-powered email forensic and campaign intelligence platform for SOC analysts (Smart India Hackathon, PS 26106).

## Stack

- Next.js 16 (App Router) + TypeScript
- Tailwind CSS v4 (design tokens defined in `src/app/globals.css`)
- shadcn/ui-style primitives — **hand-built**, not installed via the `shadcn` CLI (see note below)
- lucide-react icons
- Geist Sans / Geist Mono via `next/font/google`

## A note on shadcn/ui

The `shadcn` CLI pulls component source from `ui.shadcn.com` at install time. That
registry was not reachable from the sandbox this project was built in, so the
primitives in `src/components/ui/` were hand-written to match standard shadcn
source, restyled against this project's design tokens. They are drop-in
compatible: if you later run `npx shadcn@latest add <component>` from a normal
dev machine, it will happily overwrite/extend these files using the same
`components.json` aliases (`@/components/ui`, `@/lib/utils`, etc.).

## Getting started

```bash
npm install
npm run dev
```

Visit http://localhost:3000 — it redirects to `/dashboard`.

## Project structure

```
src/
  app/
    (app)/            route group sharing the AppShell (TopBar + Sidebar)
      dashboard/
      analyze/
      emails/
      campaigns/
      hunter/
      cases/
      reports/
      admin/          role-gated (administrator only)
    layout.tsx        root layout, forces dark theme, loads Geist fonts
    globals.css        design tokens (colors, radius) mapped into Tailwind's @theme
  components/
    ui/                hand-built shadcn-style primitives
    shell/              TopBar, Sidebar, AppShell, PageHeader
    cybersentry/        product-specific components (SeverityBadge, KpiCard, EmptyState, ErrorState)
  config/
    nav.ts              primary navigation, role-gated
  lib/
    utils.ts            cn() helper
    mock/                typed mock data adapters (swap for real API calls)
  types/
    index.ts             shared domain types (Severity, TrustState, CampaignState, etc.)
```

## Design tokens

All color is driven by CSS variables in `globals.css` and exposed as Tailwind
utilities (`bg-bg-surface`, `text-state-critical`, `border-border-default`,
etc.). Never hardcode hex values in components — extend the token set instead.

Technical/forensic values (hashes, IPs, domains, URLs, IDs) should use the
`.font-technical` class (Geist Mono / JetBrains Mono fallback), not the default
sans body font.

## What's built vs. what's next

This pass covers the **shell**: token system, dark theme, top bar with global
search, role-aware sidebar, and a navigable placeholder for all 8 primary
sections. The Dashboard and Analyze screens are the most fleshed out.

Not yet built (next passes): Analysis Overview, Evidence panels, Header
Timeline, Authentication cards, URL/Infrastructure tables, PhishDNA, Campaign
Evolution Timeline, What Changed comparison, Attack Intent Graph, Case
workspace tabs, and Reports export flow — all called out in the design spec's
sections 11–24.
