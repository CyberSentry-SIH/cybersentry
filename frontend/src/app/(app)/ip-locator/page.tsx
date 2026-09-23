"use client";

import { useState, useEffect, type FormEvent } from "react";
import {
  Globe, Search, MapPin, Server, Shield, Clock,
  ExternalLink, Copy, Check, Loader2, AlertTriangle, Compass,
} from "lucide-react";
import { PageHeader } from "@/components/shell/page-header";
import { api } from "@/lib/api";

interface GeoData {
  ip: string;
  query: string;
  hostname?: string;
  country_name?: string;
  country_code2?: string;
  country_flag?: string;
  city?: string;
  state_prov?: string;
  zipcode?: string;
  latitude?: string | null;
  longitude?: string | null;
  isp?: string;
  organization?: string;
  asn?: string;
  timezone?: string;
  continent_name?: string;
  location_note?: string;
  currency?: { code: string; name: string; symbol: string };
  threat?: {
    is_tor: boolean;
    is_proxy: boolean;
    is_anonymous: boolean;
    threat_score: number;
  };
  source?: string;
  error?: string;
}

const SAMPLE_IPS = [
  { ip: "185.220.101.5",  label: "Tor Exit",        color: "rose"    },
  { ip: "194.26.29.112",  label: "Phish Origin",    color: "amber"   },
  { ip: "8.8.8.8",        label: "Google DNS",      color: "blue"    },
  { ip: "1.1.1.1",        label: "Cloudflare",      color: "cyan"    },
  { ip: "117.99.94.128",  label: "Consumer ISP",    color: "emerald" },
];

function InfoCard({
  icon: Icon,
  title,
  color,
  rows,
}: {
  icon: any;
  title: string;
  color: string;
  rows: { label: string; value?: string | null; badge?: { text: string; ok: boolean } }[];
}) {
  return (
    <div className="rounded-2xl border border-slate-300 dark:border-slate-800 bg-white dark:bg-slate-900/80 shadow-sm overflow-hidden transition-colors duration-200">
      <div className={`flex items-center gap-2.5 px-4 py-3 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-${color}-950/30`}>
        <div className={`flex h-7 w-7 items-center justify-center rounded-lg bg-slate-100 dark:bg-${color}-950/60 border border-slate-300 dark:border-${color}-900/50`}>
          <Icon className={`h-3.5 w-3.5 text-cyan-600 dark:text-${color}-400`} />
        </div>
        <span className="text-xs font-mono font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider">{title}</span>
      </div>
      <dl className="divide-y divide-slate-100 dark:divide-slate-800/60 px-4 py-2">
        {rows.map((r) => (
          <div key={r.label} className="flex items-center justify-between gap-3 py-2">
            <dt className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-500 shrink-0">{r.label}</dt>
            {r.badge ? (
              <dd>
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                  r.badge.ok
                    ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-900/50"
                    : "bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:text-rose-400 border border-rose-300 dark:border-rose-900/50"
                }`}>
                  {r.badge.text}
                </span>
              </dd>
            ) : (
              <dd className="text-xs font-mono text-slate-800 dark:text-slate-300 text-right truncate max-w-[160px]">
                {r.value || <span className="text-slate-400 dark:text-slate-600">N/A</span>}
              </dd>
            )}
          </div>
        ))}
      </dl>
    </div>
  );
}

export default function IpLocatorPage() {
  const [query, setQuery] = useState("185.220.101.5");
  const [loading, setLoading] = useState(false);
  const [geoResult, setGeoResult] = useState<GeoData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function performLookup(target: string) {
    if (!target.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const data = await api.lookupGeo(target.trim());
      setGeoResult(data);
    } catch (err: any) {
      setError(err.message || "Failed to locate IP address.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { performLookup("185.220.101.5"); }, []);

  function handleSearch(e: FormEvent) {
    e.preventDefault();
    performLookup(query);
  }

  function handleCopy() {
    if (!geoResult) return;
    navigator.clipboard.writeText(JSON.stringify(geoResult, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const mapUrl =
    geoResult?.latitude && geoResult?.longitude
      ? `https://www.openstreetmap.org/?mlat=${geoResult.latitude}&mlon=${geoResult.longitude}#map=12/${geoResult.latitude}/${geoResult.longitude}`
      : null;

  const threatScore = geoResult?.threat?.threat_score ?? 0;

  return (
    <div className="flex flex-col min-h-full pb-16">
      <PageHeader
        section="Investigation"
        title="IP Geolocation Intelligence"
        description="Real-time geographic attribution, ISP infrastructure, ASN networks, and threat indicators for any IP or hostname."
        meta={[
          { label: "TELEMETRY", value: "Real-Time" },
          { label: "DATABASE", value: "IPGeo + Host" },
        ]}
        actions={
          geoResult && (
            <button onClick={handleCopy} className="btn-secondary text-xs">
              {copied ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
              {copied ? "Copied JSON" : "Export JSON"}
            </button>
          )
        }
      />

      <div className="p-6 space-y-6">
        {/* Search panel */}
        <div className="rounded-2xl border border-slate-300 dark:border-slate-800 bg-white dark:bg-slate-900/80 shadow-sm p-5 space-y-4 transition-colors duration-200">
          <form onSubmit={handleSearch} className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400 pointer-events-none" />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Enter IPv4, IPv6 or hostname (e.g. 185.220.101.5)"
                className="w-full pl-10 pr-4 py-2.5 rounded-xl border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 text-sm font-mono text-slate-900 dark:text-slate-200 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 transition-colors"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="btn-primary text-sm px-6 disabled:opacity-50"
            >
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Globe className="h-4 w-4" />}
              {loading ? "Locating…" : "Locate IP"}
            </button>
          </form>

          {/* Quick-test pills */}
          <div className="flex flex-wrap items-center gap-2 pt-3 border-t border-slate-200 dark:border-slate-800">
            <span className="text-[10px] font-mono font-bold uppercase tracking-widest text-slate-500 dark:text-slate-400">Quick Test:</span>
            {SAMPLE_IPS.map((s) => (
              <button
                key={s.ip}
                type="button"
                onClick={() => { setQuery(s.ip); performLookup(s.ip); }}
                className="text-[11px] font-mono px-2.5 py-1 rounded-full border border-slate-300 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:border-cyan-500 hover:text-cyan-600 dark:hover:text-cyan-400 transition-colors cursor-pointer"
              >
                {s.label} · {s.ip}
              </button>
            ))}
          </div>
        </div>

        {/* Error */}
        {error && (
          <div className="rounded-xl border border-rose-300 dark:border-rose-900/50 bg-rose-50 dark:bg-rose-950/30 p-4 flex items-center gap-3">
            <AlertTriangle className="h-4 w-4 text-rose-600 dark:text-rose-400 shrink-0" />
            <div>
              <p className="text-xs font-bold font-mono text-rose-700 dark:text-rose-300">Lookup Failed</p>
              <p className="text-xs text-rose-600 dark:text-rose-400 mt-0.5">{error}</p>
            </div>
          </div>
        )}

        {/* Loading skeleton */}
        {loading && !geoResult && (
          <div className="rounded-2xl border border-slate-300 dark:border-slate-800 bg-white dark:bg-slate-900/60 p-8 flex flex-col items-center gap-3">
            <div className="h-8 w-8 animate-spin rounded-full border-2 border-cyan-500 border-t-transparent" />
            <p className="text-xs font-mono text-slate-500">Running geolocation trace…</p>
          </div>
        )}

        {/* Result */}
        {geoResult && (
          <div className="space-y-5">
            {/* Hero dossier card */}
            <div className="rounded-2xl border border-slate-300 dark:border-cyan-900/30 bg-gradient-to-r from-white via-cyan-50/50 to-blue-50/50 dark:from-slate-900 dark:via-cyan-950/30 dark:to-slate-900 p-6 relative overflow-hidden shadow-sm">
              <div className="absolute top-0 inset-x-0 h-px bg-gradient-to-r from-transparent via-cyan-500/40 to-transparent" />
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-5">
                <div className="space-y-1.5">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="px-2.5 py-0.5 rounded-full bg-cyan-100 dark:bg-cyan-950/60 border border-cyan-300 dark:border-cyan-800/50 text-cyan-800 dark:text-cyan-400 text-[10px] font-mono font-bold uppercase tracking-wider">
                      Target Query
                    </span>
                    <h2 className="text-2xl font-bold font-mono text-slate-900 dark:text-white">{geoResult.ip}</h2>
                    {geoResult.country_code2 && (
                      <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                        [{geoResult.country_code2}]
                      </span>
                    )}
                  </div>
                  <p className="text-sm text-slate-600 dark:text-slate-400 flex items-center gap-2 font-mono">
                    <MapPin className="h-3.5 w-3.5 text-cyan-600 dark:text-cyan-400" />
                    {[geoResult.city, geoResult.state_prov, geoResult.country_name].filter(Boolean).join(", ") || "Location unavailable"}
                  </p>
                  {geoResult.hostname && (
                    <p className="text-xs text-slate-500 font-mono">
                      RDNS: {geoResult.hostname}
                    </p>
                  )}
                </div>

                <div className="flex items-center gap-4 flex-wrap">
                  {/* Threat score ring */}
                  <div className="flex flex-col items-center justify-center h-20 w-20 rounded-2xl border-2 border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 shadow-sm relative">
                    <span className={`text-2xl font-bold font-mono ${
                      threatScore > 60 ? "text-rose-600 dark:text-rose-400" :
                      threatScore > 30 ? "text-amber-600 dark:text-amber-400" :
                      "text-emerald-600 dark:text-emerald-400"
                    }`}>
                      {threatScore}
                    </span>
                    <span className="text-[9px] font-mono text-slate-500 dark:text-slate-400 uppercase tracking-wider">/100 RISK</span>
                  </div>

                  <div className="flex flex-col gap-2">
                    {[
                      { label: "TOR", active: geoResult.threat?.is_tor },
                      { label: "PROXY", active: geoResult.threat?.is_proxy },
                      { label: "ANON", active: geoResult.threat?.is_anonymous },
                    ].map(({ label, active }) => (
                      <span key={label} className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                        active
                          ? "bg-rose-100 dark:bg-rose-950/60 border border-rose-300 dark:border-rose-900/50 text-rose-800 dark:text-rose-400"
                          : "bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-400"
                      }`}>
                        {label}: {active ? "⚠ YES" : "✓ NO"}
                      </span>
                    ))}
                  </div>

                  <div className="rounded-xl border border-slate-300 dark:border-slate-800 bg-white/80 dark:bg-slate-900/80 px-4 py-3 text-center shadow-sm">
                    <p className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-500">Source</p>
                    <p className="text-xs font-bold text-cyan-600 dark:text-cyan-400 font-mono mt-0.5">{geoResult.source || "IP_ENRICHMENT"}</p>
                  </div>
                </div>
              </div>
            </div>

            {/* 4-column detail grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
              <InfoCard
                icon={MapPin}
                title="Exact Location"
                color="cyan"
                rows={[
                  { label: "City", value: geoResult.city },
                  { label: "Region", value: geoResult.state_prov },
                  { label: "Country", value: [geoResult.country_name, geoResult.country_code2 ? `(${geoResult.country_code2})` : ""].filter(Boolean).join(" ") },
                  { label: "Postal", value: geoResult.zipcode },
                  { label: "Continent", value: geoResult.continent_name },
                ]}
              />
              <InfoCard
                icon={Server}
                title="ISP & Network"
                color="blue"
                rows={[
                  { label: "ISP", value: geoResult.isp },
                  { label: "Organization", value: geoResult.organization || geoResult.isp },
                  { label: "ASN", value: geoResult.asn },
                  { label: "RDNS/Hostname", value: geoResult.hostname || geoResult.ip },
                ]}
              />
              <InfoCard
                icon={Compass}
                title="Coordinates"
                color="indigo"
                rows={[
                  { label: "Latitude", value: geoResult.latitude ?? undefined },
                  { label: "Longitude", value: geoResult.longitude ?? undefined },
                  { label: "Timezone", value: geoResult.timezone },
                  { label: "Currency", value: geoResult.currency?.code && geoResult.currency.code !== "N/A"
                    ? `${geoResult.currency.name} (${geoResult.currency.symbol})`
                    : undefined },
                ]}
              />
              <InfoCard
                icon={Shield}
                title="Threat Signals"
                color="rose"
                rows={[
                  { label: "Tor Exit", badge: { text: geoResult.threat?.is_tor ? "YES – TOR" : "NO", ok: !geoResult.threat?.is_tor } },
                  { label: "Proxy/Anon", badge: { text: (geoResult.threat?.is_proxy || geoResult.threat?.is_anonymous) ? "YES" : "CLEAN", ok: !geoResult.threat?.is_proxy && !geoResult.threat?.is_anonymous } },
                  { label: "Threat Score", value: `${threatScore} / 100` },
                ]}
              />
            </div>

            {/* Map link */}
            {mapUrl && (
              <a
                href={mapUrl}
                target="_blank"
                rel="noreferrer"
                className="flex items-center justify-center gap-2 rounded-xl border border-cyan-300 dark:border-cyan-900/40 bg-cyan-50 dark:bg-cyan-950/20 py-3 text-sm font-mono text-cyan-700 dark:text-cyan-400 hover:bg-cyan-100 dark:hover:bg-cyan-950/40 transition-colors shadow-sm"
              >
                <ExternalLink className="h-4 w-4" />
                View location on OpenStreetMap
              </a>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
