import React, { useEffect, useState } from 'react';
import { 
  Globe, 
  MapPin, 
  AlertTriangle, 
  ShieldCheck, 
  ShieldAlert, 
  Info, 
  Server, 
  Network, 
  Cloud, 
  ExternalLink, 
  Copy, 
  Check, 
  Terminal, 
  ArrowRight, 
  Clock, 
  Layers, 
  Lock, 
  Cpu, 
  RefreshCw,
  HelpCircle,
  FileText
} from 'lucide-react';
import { api } from '../services/api';

// Helper for infrastructure badge style
function getInfraBadge(tag) {
  switch (tag) {
    case 'Cloud Provider':
    case 'cloud':
      return {
        label: 'Cloud Provider',
        color: 'bg-purple-950/80 text-purple-300 border-purple-800/60',
        icon: Cloud,
      };
    case 'CDN':
    case 'cdn':
      return {
        label: 'CDN Network',
        color: 'bg-sky-950/80 text-sky-300 border-sky-800/60',
        icon: Network,
      };
    case 'Email Provider':
    case 'email_provider':
      return {
        label: 'Email Provider / ESP',
        color: 'bg-emerald-950/80 text-emerald-300 border-emerald-800/60',
        icon: Server,
      };
    case 'VPN/Proxy':
    case 'anonymizer':
      return {
        label: 'VPN / Proxy / Anonymizer',
        color: 'bg-rose-950/80 text-rose-300 border-rose-800/60',
        icon: ShieldAlert,
      };
    case 'Private LAN':
    case 'private':
      return {
        label: 'Internal LAN / Private',
        color: 'bg-slate-800 text-slate-300 border-slate-700',
        icon: Lock,
      };
    case 'Documentation':
    case 'documentation':
      return {
        label: 'RFC Benchmark / Testbed',
        color: 'bg-amber-950/80 text-amber-300 border-amber-800/60',
        icon: FileText,
      };
    default:
      return {
        label: 'Commercial / Transit ISP',
        color: 'bg-cyan-950/80 text-cyan-300 border-cyan-800/60',
        icon: Globe,
      };
  }
}

// Helper for exact IP type badge
function getIpTypeBadge(type) {
  const norm = (type || '').toLowerCase();
  if (norm.includes('public')) {
    return 'bg-emerald-950 text-emerald-300 border-emerald-700/60';
  }
  if (norm.includes('private')) {
    return 'bg-blue-950 text-blue-300 border-blue-700/60';
  }
  if (norm.includes('doc')) {
    return 'bg-amber-950 text-amber-300 border-amber-700/60';
  }
  if (norm.includes('loop')) {
    return 'bg-purple-950 text-purple-300 border-purple-700/60';
  }
  if (norm.includes('link')) {
    return 'bg-teal-950 text-teal-300 border-teal-700/60';
  }
  return 'bg-slate-800 text-slate-300 border-slate-700';
}

export default function GeolocationPage() {
  const [analyses, setAnalyses] = useState([]);
  const [selectedAnalysis, setSelectedAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [copiedIndex, setCopiedIndex] = useState(null);
  const [filterType, setFilterType] = useState('ALL');

  useEffect(() => {
    async function loadData() {
      try {
        const list = await api.getAnalyses();
        setAnalyses(list);
        if (list.length > 0) {
          const detail = await api.getAnalysis(list[0].id);
          setSelectedAnalysis(detail);
        }
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const handleSelect = async (id) => {
    setLoading(true);
    try {
      const detail = await api.getAnalysis(id);
      setSelectedAnalysis(detail);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text, idx) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2500);
  };

  const geolocations = selectedAnalysis?.geolocations || [];

  // Filter IPs
  const filteredGeos = geolocations.filter((geo) => {
    if (filterType === 'PUBLIC') return geo.is_public;
    if (filterType === 'NON_PUBLIC') return !geo.is_public;
    return true;
  });

  const publicCount = geolocations.filter((g) => g.is_public).length;
  const nonPublicCount = geolocations.length - publicCount;

  return (
    <div className="p-6 md:p-8 space-y-8 max-w-7xl mx-auto">
      {/* Title & Navigation */}
      <div className="border-b border-slate-800 pb-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2.5 bg-cyan-950/80 border border-cyan-800/60 rounded-xl">
              <Globe className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <h1 className="text-2xl font-black text-slate-100 tracking-tight">
                IP Geolocation & Routing Intelligence
              </h1>
              <p className="text-xs text-slate-400 mt-0.5">
                Multi-Hop MTA Path Reconstruction • Autonomous System (ASN) Profiling • Forensic Geolocation Disclaimers
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-[11px] font-mono text-cyan-400 bg-cyan-950/50 px-2.5 py-1 rounded border border-cyan-800/40">
            RFC 5322 Received Parser Active
          </span>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* FORENSIC MANDATE BANNER: 3-WAY NON-EQUIVALENCE PRINCIPLE                  */}
      {/* ========================================================================= */}
      <div className="p-5 bg-gradient-to-r from-amber-950/40 via-slate-900 to-slate-900 border border-amber-600/40 rounded-xl space-y-3 shadow-lg">
        <div className="flex items-start space-x-3">
          <div className="p-2 bg-amber-900/30 border border-amber-600/50 rounded-lg shrink-0 mt-0.5">
            <AlertTriangle className="w-5 h-5 text-amber-400" />
          </div>
          <div className="space-y-2 flex-1 text-xs">
            <div className="flex items-center justify-between">
              <span className="font-black uppercase tracking-wider text-amber-300 text-xs">
                Forensic Non-Equivalence Doctrine & Accuracy Mandate:
              </span>
              <span className="text-[10px] font-mono bg-amber-950 text-amber-300 px-2 py-0.5 rounded border border-amber-700/50 font-semibold">
                NEVER ASSUME PHYSICAL RESIDENCE
              </span>
            </div>
            <p className="text-slate-300 leading-relaxed">
              In cybersecurity and forensic jurisprudence, an extracted IP address identifies the <strong>network data center, 
              border gateway, or mail relay server</strong> that transmitted the SMTP payload. It does <strong>NOT</strong> prove 
              the physical home or office location of the human sender.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2 text-[11px]">
              <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800 space-y-1">
                <span className="font-bold text-cyan-300 block">1. Network Geolocation (PoP)</span>
                <p className="text-slate-400 text-[10px] leading-normal">
                  Identifies the geographic data center / BGP Point-of-Presence where the IP address is routed.
                </p>
              </div>
              <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800 space-y-1">
                <span className="font-bold text-purple-300 block">2. Mail Relay Infrastructure</span>
                <p className="text-slate-400 text-[10px] leading-normal">
                  Identifies the Mail Transfer Agent (MTA) role: Originating Gateway, Intermediary Relay, or Destination MX.
                </p>
              </div>
              <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800 space-y-1">
                <span className="font-bold text-amber-400 block">3. Sender Physical Location</span>
                <p className="text-amber-200/90 text-[10px] leading-normal">
                  <strong className="text-amber-300">UNVERIFIED.</strong> Senders may use webmail, VPNs, mobile proxies, or spoofing. IP never confirms residence.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Investigation Selector & Summary Stats */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Selector */}
        <div className="lg:col-span-3 bg-slate-900 border border-slate-800 p-4 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center space-x-2">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
              Active Investigation:
            </span>
          </div>
          <select
            onChange={(e) => handleSelect(e.target.value)}
            value={selectedAnalysis?.id || ''}
            className="bg-slate-950 border border-slate-700 text-xs text-slate-200 rounded-lg px-3 py-2 focus:outline-none focus:border-cyan-500 font-mono w-full sm:w-auto max-w-lg truncate"
          >
            {analyses.map((a) => (
              <option key={a.id} value={a.id}>
                #{a.id} — {a.filename} | {a.subject || '(No Subject)'} [{a.risk_level}]
              </option>
            ))}
          </select>
        </div>

        {/* Quick Filter */}
        <div className="bg-slate-900 border border-slate-800 p-3 rounded-xl flex items-center justify-around text-xs">
          <button
            onClick={() => setFilterType('ALL')}
            className={`px-3 py-1.5 rounded-lg font-bold transition-colors ${
              filterType === 'ALL'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            All ({geolocations.length})
          </button>
          <button
            onClick={() => setFilterType('PUBLIC')}
            className={`px-3 py-1.5 rounded-lg font-bold transition-colors ${
              filterType === 'PUBLIC'
                ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Public ({publicCount})
          </button>
          <button
            onClick={() => setFilterType('NON_PUBLIC')}
            className={`px-3 py-1.5 rounded-lg font-bold transition-colors ${
              filterType === 'NON_PUBLIC'
                ? 'bg-amber-950 text-amber-300 border border-amber-800'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Filtered ({nonPublicCount})
          </button>
        </div>
      </div>

      {/* Main Extracted IP Endpoints Grid */}
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
            <Layers className="w-4 h-4 text-cyan-400" />
            <span>Extracted IP Endpoints & Routing Evidence ({filteredGeos.length})</span>
          </h2>
          <span className="text-[10px] text-slate-500 font-mono">
            {selectedAnalysis?.filename ? `Source: ${selectedAnalysis.filename}` : ''}
          </span>
        </div>

        {filteredGeos.length === 0 ? (
          <div className="p-12 bg-slate-900/60 border border-slate-800 rounded-xl text-center space-y-3">
            <AlertTriangle className="w-8 h-8 text-amber-400 mx-auto" />
            <h3 className="text-sm font-bold text-slate-200">
              No IP addresses match the selected filter criteria.
            </h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
              If this email had no Received headers, all coordinates remain strictly un-fabricated in accordance with forensic guidelines.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-6">
            {filteredGeos.map((geo, idx) => {
              const infra = getInfraBadge(geo.infrastructure_tag || geo.infrastructure_type);
              const InfraIcon = infra.icon;

              return (
                <div
                  key={idx}
                  className="bg-slate-900 border border-slate-800 rounded-xl p-5 md:p-6 space-y-6 shadow-md transition-all hover:border-slate-700"
                >
                  {/* Card Header: Long IP without truncation + Badges with responsive wrap */}
                  <div className="flex flex-col lg:flex-row lg:items-center justify-between pb-4 border-b border-slate-800 gap-3">
                    <div className="space-y-1.5 flex-1 min-w-0">
                      <div className="flex items-center space-x-2 text-[11px] text-slate-400 font-mono">
                        <span className="font-bold text-cyan-400">
                          {geo.hop_order != null ? `HOP #${geo.hop_order}` : 'SOURCE HOP'}
                        </span>
                        {geo.total_hops && (
                          <span>of {geo.total_hops} in transmission chain</span>
                        )}
                        <span>•</span>
                        <span>{geo.relay_role || 'SMTP Transfer Node'}</span>
                      </div>

                      {/* Complete IP Display - Non-truncated, selectable, wrapping cleanly */}
                      <div className="flex items-center space-x-3">
                        <span className="font-mono text-base md:text-lg font-black text-slate-100 break-all select-all tracking-wide">
                          {geo.ip}
                        </span>
                      </div>
                    </div>

                    {/* Responsive Badges Container */}
                    <div className="flex flex-wrap items-center gap-2 shrink-0">
                      {/* Exact IP Classification */}
                      <span className={`text-[10px] font-bold uppercase px-2.5 py-1 rounded border font-mono ${getIpTypeBadge(geo.ip_type)}`}>
                        {geo.ip_type || (geo.is_public ? 'Public' : 'Private')}
                      </span>

                      {/* Infrastructure Category */}
                      <span className={`text-[10px] font-bold px-2.5 py-1 rounded border flex items-center space-x-1.5 ${infra.color}`}>
                        <InfraIcon className="w-3 h-3" />
                        <span>{geo.infrastructure_type || infra.label}</span>
                      </span>

                      {/* Confidence Score Pill */}
                      <span className={`text-[10px] font-bold px-2.5 py-1 rounded border font-mono ${
                        geo.confidence_score >= 80 
                          ? 'bg-emerald-950 text-emerald-300 border-emerald-800/60'
                          : geo.confidence_score >= 50
                          ? 'bg-amber-950 text-amber-300 border-amber-800/60'
                          : 'bg-slate-800 text-slate-400 border-slate-700'
                      }`}>
                        Confidence: {geo.confidence_score != null ? `${geo.confidence_score}%` : 'N/A'}
                      </span>
                    </div>
                  </div>

                  {/* ========================================================================= */}
                  {/* 3-WAY FORENSIC LOCATION DISTINCTION (REQUIREMENT 6 & 7)                   */}
                  {/* ========================================================================= */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {/* 1. Network Geolocation */}
                    <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px] flex items-center space-x-1">
                          <Globe className="w-3.5 h-3.5 text-cyan-400" />
                          <span>1. Network Geolocation</span>
                        </span>
                        <span className="text-[9px] font-mono bg-cyan-950 text-cyan-300 px-1.5 py-0.5 rounded">
                          PoP Footprint
                        </span>
                      </div>
                      <p className="font-semibold text-slate-100 text-sm">
                        {geo.is_geolocatable && geo.country && geo.country !== 'Not geolocatable'
                          ? `${geo.city || 'Unknown City'}, ${geo.region || ''} ${geo.country}`
                          : <span className="text-amber-400">Not geolocatable</span>}
                      </p>
                      <div className="text-[11px] text-slate-400 space-y-1 font-mono">
                        <div>Coordinates: {geo.latitude != null && geo.longitude != null ? `${geo.latitude}, ${geo.longitude}` : 'N/A'}</div>
                        <div>Timezone: {geo.timezone || 'N/A'}</div>
                      </div>
                    </div>

                    {/* 2. Mail Relay Infrastructure */}
                    <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px] flex items-center space-x-1">
                          <Server className="w-3.5 h-3.5 text-purple-400" />
                          <span>2. Mail Relay Role</span>
                        </span>
                        <span className="text-[9px] font-mono bg-purple-950 text-purple-300 px-1.5 py-0.5 rounded">
                          MTA Node
                        </span>
                      </div>
                      <p className="font-semibold text-slate-200 text-xs">
                        {geo.relay_role || 'Intermediate Mail Relay'}
                      </p>
                      <div className="text-[11px] text-slate-400 space-y-1">
                        <div>ISP: <span className="text-slate-300 font-medium">{geo.isp || 'Internal/Private'}</span></div>
                        <div className="font-mono text-[10px] truncate" title={geo.asn || geo.org}>
                          ASN: {geo.asn || geo.org || 'N/A'}
                        </div>
                      </div>
                    </div>

                    {/* 3. Sender Physical Location */}
                    <div className="bg-slate-950 p-4 rounded-xl border border-amber-900/40 space-y-2">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-amber-400 font-bold uppercase tracking-wider text-[10px] flex items-center space-x-1">
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                          <span>3. Sender Physical Location</span>
                        </span>
                        <span className="text-[9px] font-mono bg-amber-950 text-amber-300 px-1.5 py-0.5 rounded font-bold">
                          UNVERIFIED
                        </span>
                      </div>
                      <p className="font-bold text-amber-300 text-xs uppercase">
                        NOT DETERMINABLE FROM IP
                      </p>
                      <p className="text-[10px] text-amber-200/80 leading-relaxed">
                        Forensic rule: Server IP confirms MTA data center origin. Senders can route emails through webmail, corporate VPNs, or proxy relays.
                      </p>
                    </div>
                  </div>

                  {/* "Why This IP Matters" & Forensic Explanation */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                    {/* Why this IP matters */}
                    <div className="p-4 bg-slate-950/80 border border-slate-800 rounded-xl space-y-1.5">
                      <div className="flex items-center space-x-1.5 text-cyan-300 font-bold text-[11px] uppercase tracking-wider">
                        <HelpCircle className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Why This IP Matters:</span>
                      </div>
                      <p className="text-slate-300 leading-relaxed text-xs">
                        {geo.why_it_matters || (
                          geo.is_public
                            ? "Identifies an external SMTP transmission point where the message traversed the public Internet."
                            : "Internal RFC reservation. Represents private network routing or standardized test suites."
                        )}
                      </p>
                    </div>

                    {/* Forensic Analysis / Explanation */}
                    <div className="p-4 bg-slate-950/80 border border-slate-800 rounded-xl space-y-1.5">
                      <div className="flex items-center space-x-1.5 text-purple-300 font-bold text-[11px] uppercase tracking-wider">
                        <ShieldCheck className="w-3.5 h-3.5 text-purple-400" />
                        <span>Forensic Assessment:</span>
                      </div>
                      <p className="text-slate-300 leading-relaxed text-xs">
                        {geo.forensic_explanation || (
                          geo.is_public
                            ? `IP belongs to ${geo.isp || 'upstream provider'}. Coordinate accuracy score: ${geo.confidence_score}%.`
                            : geo.not_geolocatable_reason || "Non-routable IP address. Filtered from public mapping."
                        )}
                      </p>
                    </div>
                  </div>

                  {/* Non-Geolocatable Explanation Banner (If non-public) */}
                  {!geo.is_geolocatable && (
                    <div className="p-3.5 bg-amber-950/20 border border-amber-800/40 rounded-xl flex items-start space-x-3 text-xs text-amber-200">
                      <Info className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                      <div>
                        <span className="font-bold text-amber-300 uppercase tracking-wide">
                          Not Geolocatable (Standardized RFC Exclusion):
                        </span>
                        <p className="mt-0.5 text-amber-200/90 leading-relaxed">
                          {geo.not_geolocatable_reason || "This IP address is in a reserved or private range that is never advertised over public BGP routing tables."}
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Evidence Chain: Exact Received Header */}
                  <div className="pt-3 border-t border-slate-800/80 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 flex items-center space-x-1.5">
                        <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Forensic Evidence: Exact Received Header Record</span>
                      </span>
                      {geo.source_header && (
                        <button
                          onClick={() => copyToClipboard(geo.source_header, idx)}
                          className="flex items-center space-x-1 text-[11px] text-slate-400 hover:text-slate-200 bg-slate-950 px-2.5 py-1 rounded border border-slate-800 font-mono transition-colors"
                        >
                          {copiedIndex === idx ? (
                            <>
                              <Check className="w-3 h-3 text-emerald-400" />
                              <span className="text-emerald-400">Copied</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" />
                              <span>Copy Header</span>
                            </>
                          )}
                        </button>
                      )}
                    </div>

                    <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] font-mono text-slate-300 whitespace-pre-wrap break-all leading-relaxed overflow-x-auto">
                      {geo.source_header || `Extracted directly from message body / non-standard envelope: ${geo.ip}`}
                    </pre>
                  </div>

                  {/* Interactive Map Visualizer - ONLY WHEN VALID COORDINATES EXIST */}
                  {geo.latitude != null && geo.longitude != null ? (
                    <div className="pt-4 border-t border-slate-800 space-y-3">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-bold text-slate-200 flex items-center space-x-1.5">
                          <MapPin className="w-4 h-4 text-cyan-400" />
                          <span>Network PoP Geographic Visualization ({geo.city}, {geo.country})</span>
                        </span>
                        <a
                          href={`https://www.openstreetmap.org/?mlat=${geo.latitude}&mlon=${geo.longitude}#map=12/${geo.latitude}/${geo.longitude}`}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center space-x-1 text-cyan-400 hover:text-cyan-300 font-semibold"
                        >
                          <span>Open in OpenStreetMap</span>
                          <ExternalLink className="w-3 h-3 ml-0.5" />
                        </a>
                      </div>

                      <div className="rounded-xl overflow-hidden border border-slate-800 bg-slate-950 shadow-inner">
                        <iframe
                          title={`OpenStreetMap for ${geo.ip}`}
                          className="w-full h-64 border-0"
                          src={`https://www.openstreetmap.org/export/embed.html?bbox=${geo.longitude - 0.08}%2C${geo.latitude - 0.08}%2C${geo.longitude + 0.08}%2C${geo.latitude + 0.08}&layer=mapnik&marker=${geo.latitude}%2C${geo.longitude}`}
                        />
                      </div>
                      <p className="text-[10px] text-slate-400 italic">
                        Notice: Coordinates represent the server data center or upstream network PoP, not the physical home of the sender.
                      </p>
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
