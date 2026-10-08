import React, { useState, useEffect } from 'react';
import { 
  UploadCloud, 
  FileText, 
  AlertCircle, 
  CheckCircle2, 
  ShieldAlert, 
  Terminal, 
  Paperclip,
  ExternalLink,
  ChevronRight,
  Fingerprint,
  Globe,
  MapPin,
  Info,
  Clock,
  Layers,
  ShieldCheck,
  Check,
  Copy
} from 'lucide-react';
import { api } from '../services/api';
import { ScoreGauge, SeverityBadge, AuthBadge } from '../components/ScoreGauge';

export default function EmailAnalyzerPage() {
  const [activeTab, setActiveTab] = useState('upload'); // 'upload' | 'paste'
  const [file, setFile] = useState(null);
  const [rawText, setRawText] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const [samples, setSamples] = useState([]);
  const [selectedSampleInfo, setSelectedSampleInfo] = useState(null);
  const [copiedHeaderIndex, setCopiedHeaderIndex] = useState(null);

  useEffect(() => {
    async function loadSamples() {
      try {
        const list = await api.getSamples();
        setSamples(list);
      } catch (err) {
        console.error('Failed to load sample emails:', err);
      }
    }
    loadSamples();
  }, []);

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setSelectedSampleInfo(null);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
      setSelectedSampleInfo(null);
    }
  };

  const loadAndAnalyzeSample = async (sampleItem) => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getSampleContent(sampleItem.filename);
      setRawText(data.content);
      setSelectedSampleInfo(sampleItem);
      setActiveTab('paste');
      const analysisData = await api.analyzeText(data.content, sampleItem.filename);
      setResult(analysisData);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  const runAnalysis = async () => {
    setLoading(true);
    setError(null);
    try {
      let data;
      if (activeTab === 'upload') {
        if (!file) throw new Error('Please select or drop an .eml email file.');
        data = await api.analyzeFile(file);
      } else {
        if (!rawText.trim()) throw new Error('Please enter raw email headers and text.');
        data = await api.analyzeText(rawText);
      }
      setResult(data);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  const copyHeaderToClipboard = (text, idx) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedHeaderIndex(idx);
    setTimeout(() => setCopiedHeaderIndex(null), 2000);
  };

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Title */}
      <div className="border-b border-slate-800 pb-5">
        <h1 className="text-2xl font-black text-slate-100 tracking-tight flex items-center space-x-3">
          <span>Email Threat Sandbox & Deep Parser</span>
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Upload RFC 5322 emails (.eml) or paste raw headers to initiate ML classification, SPF/DKIM/DMARC audits & forensic extraction.
        </p>
      </div>

      {/* Synthetic Dataset Quick Loader */}
      <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex flex-col space-y-3 text-xs">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2 text-slate-300">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span className="font-semibold uppercase tracking-wider text-slate-300">Synthetic Benchmark Test Cases:</span>
            <span className="text-[10px] bg-amber-950 text-amber-300 border border-amber-800/40 px-2 py-0.5 rounded font-bold uppercase">
              DEMO / SYNTHETIC DATA
            </span>
          </div>
          <span className="text-[11px] text-slate-400">Click any scenario to parse & verify</span>
        </div>

        <div className="flex flex-wrap gap-2 pt-1">
          {samples.length > 0 ? (
            samples.map((s) => (
              <button
                key={s.filename}
                onClick={() => loadAndAnalyzeSample(s)}
                className={`px-3 py-1.5 rounded font-medium transition text-[11px] border ${
                  s.filename.includes('test_a')
                    ? 'bg-slate-800/80 hover:bg-slate-700 text-slate-200 border-slate-600'
                    : s.filename.includes('test_b')
                    ? 'bg-blue-950/70 hover:bg-blue-900/80 text-blue-300 border-blue-700/50'
                    : s.filename.includes('test_c')
                    ? 'bg-amber-950/70 hover:bg-amber-900/80 text-amber-300 border-amber-700/50'
                    : s.filename.includes('test_d')
                    ? 'bg-cyan-950/70 hover:bg-cyan-900/80 text-cyan-300 border-cyan-700/50'
                    : s.filename.includes('test_e')
                    ? 'bg-purple-950/70 hover:bg-purple-900/80 text-purple-300 border-purple-700/50'
                    : s.filename.includes('phishing')
                    ? 'bg-red-950/60 hover:bg-red-900/80 text-red-300 border-red-700/50'
                    : s.filename.includes('legitimate')
                    ? 'bg-emerald-950/60 hover:bg-emerald-900/80 text-emerald-300 border-emerald-700/50'
                    : s.filename.includes('attachment')
                    ? 'bg-orange-950/60 hover:bg-orange-900/80 text-orange-300 border-orange-700/50'
                    : 'bg-slate-800 hover:bg-slate-700 text-slate-200 border-slate-700'
                }`}
                title={s.description}
              >
                {s.filename.replace('_demo.eml', '').replace(/_/g, ' ').toUpperCase()}
              </button>
            ))
          ) : (
            <span className="text-slate-400">Loading synthetic benchmark samples...</span>
          )}
        </div>
      </div>

      {selectedSampleInfo && (
        <div className="p-3 bg-slate-900/90 border border-slate-800 rounded-lg text-xs flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <span className="font-mono text-cyan-300 font-bold">{selectedSampleInfo.filename}</span>
            <span className="text-slate-400">• {selectedSampleInfo.description}</span>
          </div>
          <span className="text-[10px] text-amber-400 font-bold uppercase tracking-wider">
            SYNTHETIC BENCHMARK ARTIFACT
          </span>
        </div>
      )}

      {/* Input Section */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        {/* Tab switch */}
        <div className="flex border-b border-slate-800 text-xs font-semibold">
          <button
            onClick={() => setActiveTab('upload')}
            className={`px-6 py-3.5 flex items-center space-x-2 border-b-2 transition ${
              activeTab === 'upload'
                ? 'border-red-500 text-red-400 bg-slate-800/40'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <UploadCloud className="w-4 h-4" />
            <span>Upload .EML File</span>
          </button>
          <button
            onClick={() => setActiveTab('paste')}
            className={`px-6 py-3.5 flex items-center space-x-2 border-b-2 transition ${
              activeTab === 'paste'
                ? 'border-red-500 text-red-400 bg-slate-800/40'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-4 h-4" />
            <span>Paste Raw Email / Headers</span>
          </button>
        </div>

        <div className="p-6">
          {activeTab === 'upload' ? (
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleDrop}
              className="border-2 border-dashed border-slate-700 hover:border-slate-500 rounded-xl p-10 text-center bg-slate-950/40 transition cursor-pointer flex flex-col items-center justify-center"
            >
              <UploadCloud className="w-10 h-10 text-slate-400 mb-3" />
              <p className="text-sm font-semibold text-slate-200">
                {file ? file.name : 'Drag & drop an .eml email file here, or browse'}
              </p>
              <p className="text-xs text-slate-400 mt-1">
                RFC 822 / RFC 5322 formatted emails supported (Max 15MB)
              </p>
              <input
                type="file"
                accept=".eml,message/rfc822,text/plain"
                onChange={handleFileChange}
                className="mt-4 text-xs text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-slate-800 file:text-slate-300 hover:file:bg-slate-700 cursor-pointer"
              />
            </div>
          ) : (
            <div className="space-y-3">
              <textarea
                rows={10}
                value={rawText}
                onChange={(e) => setRawText(e.target.value)}
                placeholder="Paste raw email message with headers (From:, To:, Subject:, Received: ...) and body text here..."
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-4 font-mono text-xs text-slate-200 focus:outline-none focus:border-red-500/60 transition"
              />
            </div>
          )}

          {error && (
            <div className="mt-4 p-3 bg-red-950/50 border border-red-500/50 rounded-lg text-xs text-red-300 flex items-center space-x-2">
              <AlertCircle className="w-4 h-4 shrink-0 text-red-400" />
              <span>{error}</span>
            </div>
          )}

          <div className="mt-6 flex justify-end">
            <button
              onClick={runAnalysis}
              disabled={loading}
              className="px-6 py-2.5 bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white rounded-lg font-semibold text-xs tracking-wider uppercase transition shadow-lg shadow-red-950/60 flex items-center space-x-2"
            >
              {loading ? (
                <>
                  <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Processing Analysis Pipeline...</span>
                </>
              ) : (
                <>
                  <ShieldAlert className="w-4 h-4" />
                  <span>Execute Threat Analysis</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Analysis Results View */}
      {result && (
        <div className="space-y-8 pt-4">
          <div className="border-b border-slate-800 pb-3 flex items-center justify-between">
            <h2 className="text-lg font-bold text-slate-100 uppercase tracking-wider flex items-center space-x-2">
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              <span>Forensic Investigation Verdict</span>
            </h2>
            <span className="text-xs font-mono text-slate-400 bg-slate-900 px-3 py-1 rounded border border-slate-800">
              ID: {result.id.slice(0, 8)}...
            </span>
          </div>

          {/* Top Score & Summary Banner */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <ScoreGauge score={result.risk_score} level={result.risk_level} />

            <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl lg:col-span-2 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">
                    Executive Analysis Summary
                  </span>
                  <div className="flex items-center space-x-2">
                    <span className="text-xs text-slate-400">ML Classification:</span>
                    <span className="px-2 py-0.5 text-xs font-black uppercase rounded bg-indigo-950 text-indigo-300 border border-indigo-700/40">
                      {result.ml_result?.prediction} ({(result.ml_result?.confidence * 100).toFixed(1)}%)
                    </span>
                  </div>
                </div>
                <p className="text-sm text-slate-200 mt-3 leading-relaxed">
                  {result.executive_summary}
                </p>
              </div>

              {/* SHA256 Evidence fingerprint */}
              <div className="mt-4 pt-4 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono text-slate-400">
                <span className="flex items-center space-x-1.5">
                  <Fingerprint className="w-4 h-4 text-cyan-400" />
                  <span>SHA-256: {result.sha256}</span>
                </span>
                <span>{result.file_size_bytes} bytes</span>
              </div>
            </div>
          </div>

          {/* Envelope & Authentication Section */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Headers card */}
            <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl space-y-3 lg:col-span-2 text-xs">
              <div className="flex items-center justify-between">
                <h3 className="font-bold uppercase tracking-wider text-slate-300 text-[11px]">
                  Envelope Header Inspection
                </h3>
                <span className="text-[10px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded font-mono font-semibold">
                  FACT: EXTRACTED HEADERS
                </span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-slate-300">
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">From (Claimed Sender)</span>
                  <p className="font-mono text-slate-200 break-all">{result.sender}</p>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">To (Recipient)</span>
                  <p className="font-mono text-slate-200 break-all">{result.recipient}</p>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">Reply-To</span>
                  <p className="font-mono text-slate-200 break-all">{result.reply_to || 'None'}</p>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">Return-Path</span>
                  <p className="font-mono text-slate-200 break-all">{result.return_path || 'None'}</p>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">Date</span>
                  <p className="font-mono text-slate-200 break-all">{result.date || 'not_available'}</p>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">Message-ID</span>
                  <p className="font-mono text-slate-200 break-all">{result.message_id || 'not_available'}</p>
                </div>
                <div className="sm:col-span-2">
                  <span className="text-slate-400 block text-[10px] uppercase">Subject</span>
                  <p className="font-semibold text-slate-100">{result.subject}</p>
                </div>
              </div>
            </div>

            {/* Authentication card */}
            <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="font-bold uppercase tracking-wider text-slate-300 text-[11px]">
                  Cryptographic Authentication
                </h3>
                <span className="text-[10px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded font-mono font-semibold">
                  FACT: AUTH LOGS
                </span>
              </div>
              <div className="space-y-2">
                <AuthBadge protocol="SPF" status={result.authentication?.spf} />
                <AuthBadge protocol="DKIM" status={result.authentication?.dkim} />
                <AuthBadge protocol="DMARC" status={result.authentication?.dmarc} />
              </div>
              <div className="pt-2 text-[10px] text-slate-400 italic">
                Authentication records extracted strictly from Authentication-Results and Received-SPF headers.
              </div>
            </div>
          </div>

          {/* Threat Indicators List */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                Identified Threat Findings & Security Indicators ({result.threat_findings?.length || 0})
              </h3>
              <span className="text-[10px] bg-indigo-950 text-indigo-300 border border-indigo-800/40 px-2 py-0.5 rounded font-mono font-semibold">
                INFERENCE: THREAT ENGINE
              </span>
            </div>
            {result.threat_findings?.length === 0 ? (
              <p className="text-xs text-slate-400">No anomalous security indicators detected in email stream.</p>
            ) : (
              <div className="space-y-3">
                {result.threat_findings?.map((tf, i) => (
                  <div key={i} className="p-3.5 bg-slate-950/60 border border-slate-800 rounded-lg text-xs space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-200">{tf.indicator}</span>
                      <SeverityBadge severity={tf.severity} />
                    </div>
                    <p className="text-slate-400">{tf.reason}</p>
                    {tf.evidence && (
                      <p className="font-mono text-[11px] text-red-300/80 bg-red-950/20 px-2 py-1 rounded border border-red-900/30">
                        Evidence: {tf.evidence}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* ========================================================================= */}
          {/* IP & GEOLOCATION INTELLIGENCE SECTION (REQUIREMENT 8 - 14)                 */}
          {/* ========================================================================= */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-2">
              <div>
                <h3 className="text-base font-bold text-slate-100 flex items-center space-x-2">
                  <Globe className="w-5 h-5 text-cyan-400" />
                  <span>IP & Geolocation Intelligence</span>
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Origin MTA and intermediary relay hops extracted strictly from RFC 5322 Received headers.
                </p>
              </div>
              <div className="flex items-center space-x-2 text-[10px]">
                <span className="bg-emerald-950 text-emerald-300 border border-emerald-800/40 px-2 py-0.5 rounded font-bold uppercase tracking-wider">
                  FACT: Extracted IPs
                </span>
                <span className="bg-indigo-950 text-indigo-300 border border-indigo-800/40 px-2 py-0.5 rounded font-bold uppercase tracking-wider">
                  INFERENCE: Geolocation PoP
                </span>
              </div>
            </div>

            {/* Public IP Check / Empty Notice */}
            {!result.geolocations || result.geolocations.length === 0 ? (
              <div className="p-6 bg-slate-950 border border-slate-800 rounded-lg text-center space-y-2">
                <AlertCircle className="w-6 h-6 text-slate-400 mx-auto" />
                <p className="text-xs font-semibold text-slate-300">
                  No public IP address was found in the available email headers.
                </p>
                <p className="text-[11px] text-slate-400">
                  The analyzed email lacks Received headers or transmitting IP addresses. Geolocation coordinates were not fabricated.
                </p>
              </div>
            ) : !result.geolocations.some((g) => g.is_public && g.is_geolocatable) ? (
              <div className="p-4 bg-amber-950/20 border border-amber-800/40 rounded-lg flex items-start space-x-3 text-xs">
                <Info className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <p className="font-bold text-amber-300">
                    No public IP address was found in the available email headers.
                  </p>
                  <p className="text-amber-200/80 leading-relaxed">
                    All extracted IP addresses belong to private intranet subnets (RFC 1918) or special-purpose documentation testbeds (RFC 5737 / RFC 3849). 
                    Per RFC standards, these addresses cannot be physically geolocated on the public Internet.
                  </p>
                </div>
              </div>
            ) : null}

            {/* Extracted IP Cards Grid */}
            {result.geolocations && result.geolocations.length > 0 && (
              <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
                  {result.geolocations.map((geo, idx) => (
                    <div
                      key={idx}
                      className="bg-slate-950 border border-slate-800 rounded-xl p-5 flex flex-col justify-between space-y-4 shadow-sm hover:border-slate-700 transition-colors"
                    >
                      <div className="space-y-3">
                        {/* Header with IP and Type Badge - Responsive wrapping for long IPv6 */}
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-slate-800/80 gap-2">
                          <div className="min-w-0">
                            {geo.hop_order != null && (
                              <span className="text-[10px] font-mono font-bold text-cyan-400 uppercase tracking-wider block">
                                Hop #{geo.hop_order} {geo.total_hops ? `of ${geo.total_hops}` : ''}
                              </span>
                            )}
                            <span className="font-mono text-sm font-black text-cyan-300 tracking-wide break-all select-all">
                              {geo.ip}
                            </span>
                          </div>
                          <div className="flex flex-wrap items-center gap-1.5 shrink-0">
                            <span
                              className={`text-[9px] font-bold uppercase px-2 py-0.5 rounded border font-mono ${
                                geo.is_public
                                  ? 'bg-emerald-950 text-emerald-300 border-emerald-800/50'
                                  : geo.ip_type?.toLowerCase().includes('doc')
                                  ? 'bg-amber-950 text-amber-300 border-amber-800/50'
                                  : geo.ip_type?.toLowerCase().includes('priv')
                                  ? 'bg-blue-950 text-blue-300 border-blue-800/50'
                                  : 'bg-slate-800 text-slate-300 border-slate-700'
                              }`}
                            >
                              {geo.ip_type || (geo.is_public ? 'PUBLIC' : 'PRIVATE')}
                            </span>
                            {geo.confidence_score != null && (
                              <span className="text-[9px] font-mono font-semibold bg-slate-900 border border-slate-700 text-slate-300 px-1.5 py-0.5 rounded">
                                {geo.confidence_score}%
                              </span>
                            )}
                          </div>
                        </div>

                        {/* Infrastructure Tag & Relay Role */}
                        <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800/80 text-[11px] space-y-1">
                          <div className="flex justify-between items-center">
                            <span className="text-slate-400 text-[10px] uppercase font-semibold">Infrastructure:</span>
                            <span className="font-bold text-purple-300 truncate max-w-[170px]" title={geo.infrastructure_type}>
                              {geo.infrastructure_type || (geo.is_public ? 'Internet Transit' : 'Internal LAN')}
                            </span>
                          </div>
                          <div className="flex justify-between items-center">
                            <span className="text-slate-400 text-[10px] uppercase font-semibold">Relay Role:</span>
                            <span className="text-slate-200 truncate max-w-[170px]" title={geo.relay_role}>
                              {geo.relay_role || 'Intermediate Hop'}
                            </span>
                          </div>
                        </div>

                        {/* 3-Way Location Forensic Distinction */}
                        <div className="space-y-1.5 text-xs">
                          <div className="flex justify-between py-1 border-b border-slate-900">
                            <span className="text-slate-400 text-[11px]">Network PoP:</span>
                            <span className="font-semibold text-slate-200 text-right max-w-[170px] truncate">
                              {geo.is_geolocatable && geo.country && geo.country !== 'Unknown' && geo.country !== 'Not geolocatable' ? (
                                `${geo.city || ''}, ${geo.country}`
                              ) : (
                                <span className="text-amber-400 font-semibold">Not geolocatable</span>
                              )}
                            </span>
                          </div>
                          <div className="flex justify-between py-1 border-b border-slate-900">
                            <span className="text-slate-400 text-[11px]">ISP / ASN:</span>
                            <span className="text-slate-300 max-w-[170px] truncate text-right font-mono text-[10px]" title={`${geo.isp} | ${geo.asn}`}>
                              {geo.asn || geo.isp || 'N/A'}
                            </span>
                          </div>
                          <div className="flex justify-between py-1 border-b border-slate-900">
                            <span className="text-amber-400 text-[11px] font-semibold">Sender Physical:</span>
                            <span className="text-amber-300 font-bold text-[10px] text-right uppercase">
                              UNVERIFIED
                            </span>
                          </div>
                        </div>

                        {/* "Why This IP Matters" */}
                        {geo.why_it_matters && (
                          <div className="p-2.5 bg-slate-900/60 border border-slate-800 rounded-lg text-[10px] text-slate-300 leading-relaxed">
                            <span className="font-bold text-cyan-300 block mb-0.5 uppercase tracking-wider text-[9px]">
                              Why This IP Matters:
                            </span>
                            {geo.why_it_matters}
                          </div>
                        )}

                        {/* Not Geolocatable Explanation Box */}
                        {!geo.is_geolocatable && (
                          <div className="p-2.5 bg-amber-950/20 border border-amber-900/30 rounded-lg text-[10px] text-amber-300/90 leading-relaxed">
                            <span className="font-bold text-amber-400 block mb-0.5">Not geolocatable:</span>
                            {geo.not_geolocatable_reason || 'Address belongs to an unroutable IP range.'}
                          </div>
                        )}
                      </div>

                      {/* Map Link when coordinates available */}
                      {geo.latitude != null && geo.longitude != null ? (
                        <div className="pt-3 border-t border-slate-800/80">
                          <a
                            href={`https://www.openstreetmap.org/?mlat=${geo.latitude}&mlon=${geo.longitude}#map=12/${geo.latitude}/${geo.longitude}`}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center space-x-1.5 text-xs text-cyan-400 hover:text-cyan-300 font-semibold"
                          >
                            <MapPin className="w-3.5 h-3.5" />
                            <span>View on OpenStreetMap</span>
                            <ExternalLink className="w-3 h-3 ml-0.5" />
                          </a>
                        </div>
                      ) : (
                        <div className="text-[10px] text-slate-400 italic pt-2 border-t border-slate-800/60">
                          Coordinates restricted for private/documentation hops
                        </div>
                      )}
                    </div>
                  ))}
                </div>

                {/* Forensic Evidence Section (Exact Received Header) */}
                <div className="mt-6 pt-6 border-t border-slate-800 space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
                      <Terminal className="w-4 h-4 text-cyan-400" />
                      <span>Forensic Evidence: Exact Received Header Records</span>
                    </h4>
                    <span className="text-[10px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded font-mono font-semibold">
                      FACT: UNALTERED HEADER EVIDENCE
                    </span>
                  </div>

                  <div className="space-y-3">
                    {result.geolocations.map((geo, idx) => (
                      <div key={idx} className="bg-slate-950 border border-slate-800 rounded-lg p-3.5 text-xs space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-cyan-400 font-bold">
                            IP: {geo.ip} ({geo.ip_type})
                          </span>
                          <div className="flex items-center space-x-3">
                            <span className="text-[10px] font-mono text-slate-400">
                              {geo.source_header ? 'Source: Received Header' : 'Source: Message Body'}
                            </span>
                            {geo.source_header && (
                              <button
                                onClick={() => copyHeaderToClipboard(geo.source_header, idx)}
                                className="flex items-center space-x-1 text-[10px] text-slate-400 hover:text-slate-200 bg-slate-900 px-2 py-0.5 rounded border border-slate-800"
                              >
                                {copiedHeaderIndex === idx ? (
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
                        </div>
                        <pre className="font-mono text-[11px] text-slate-300 bg-slate-900/90 p-3 rounded border border-slate-800 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
                          {geo.source_header || `IP address ${geo.ip} was extracted directly from the email message body payload.`}
                        </pre>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Interactive Map (Rendered ONLY when valid coordinates exist!) */}
                {result.geolocations.some((g) => g.latitude != null && g.longitude != null) && (
                  <div className="mt-6 pt-6 border-t border-slate-800 space-y-4">
                    <div className="flex items-center justify-between">
                      <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
                        <MapPin className="w-4 h-4 text-cyan-400" />
                        <span>Interactive Geolocation Mapping (Public Inbounds)</span>
                      </h4>
                      <span className="text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-800/40 px-2 py-0.5 rounded font-mono font-semibold">
                        ROUTABLE PUBLIC COORDINATES
                      </span>
                    </div>

                    {result.geolocations
                      .filter((g) => g.latitude != null && g.longitude != null)
                      .map((geo, mIdx) => (
                        <div key={mIdx} className="space-y-2 bg-slate-950 p-4 rounded-xl border border-slate-800">
                          <div className="flex items-center justify-between text-xs pb-2 border-b border-slate-800">
                            <span className="font-semibold text-slate-200">
                              Resolved Target: <span className="font-mono text-cyan-400">{geo.ip}</span> ({geo.city}, {geo.region}, {geo.country})
                            </span>
                            <span className="font-mono text-[11px] text-slate-400">
                              Coordinates: {geo.latitude}, {geo.longitude}
                            </span>
                          </div>
                          <iframe
                            title={`Map for ${geo.ip}`}
                            className="w-full h-72 rounded-lg border border-slate-800"
                            src={`https://www.openstreetmap.org/export/embed.html?bbox=${geo.longitude - 0.08}%2C${geo.latitude - 0.08}%2C${geo.longitude + 0.08}%2C${geo.latitude + 0.08}&layer=mapnik&marker=${geo.latitude}%2C${geo.longitude}`}
                          />
                          <p className="text-[10px] text-slate-400 italic pt-1">
                            Notice: {geo.accuracy_notice || 'IP geolocation is approximate and does not establish physical residence.'}
                          </p>
                        </div>
                      ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Extracted URLs & Attachments */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* URLs */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 text-xs">
              <div className="flex items-center justify-between mb-3">
                <h3 className="font-bold uppercase tracking-wider text-slate-300">
                  Extracted URLs ({result.urls?.length || 0})
                </h3>
                <span className="text-[10px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded font-mono font-semibold">
                  FACT: EXTRACTED HYPERLINKS
                </span>
              </div>
              {result.urls?.length === 0 ? (
                <p className="text-slate-400">No hyperlinked URLs found in message body.</p>
              ) : (
                <div className="space-y-2">
                  {result.urls?.map((u, i) => (
                    <div key={i} className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-[11px] text-cyan-300 break-all">{u.url}</span>
                        {u.is_suspicious && <SeverityBadge severity="high" />}
                      </div>
                      <div className="text-[10px] text-slate-400 mt-1">Host: {u.host} | Scheme: {u.scheme}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Attachments */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 text-xs">
              <div className="flex items-center justify-between mb-3">
                <h3 className="font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
                  <Paperclip className="w-3.5 h-3.5" />
                  <span>Extracted Attachments ({result.attachments?.length || 0})</span>
                </h3>
                <span className="text-[10px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded font-mono font-semibold">
                  FACT: MIME INSPECTION
                </span>
              </div>
              {result.attachments?.length === 0 ? (
                <p className="text-slate-400">No file attachments enclosed in email message.</p>
              ) : (
                <div className="space-y-2">
                  {result.attachments?.map((att, i) => (
                    <div key={i} className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-bold text-slate-200">{att.filename}</span>
                        {att.is_dangerous ? <SeverityBadge severity="critical" /> : <SeverityBadge severity="low" />}
                      </div>
                      <p className="text-[10px] text-slate-400 mt-1">
                        Size: {att.size_bytes} B | MIME: {att.content_type}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Forensic Relay MTA Chain Hops (Requirement 13) */}
          {result.forensic_hops && result.forensic_hops.length > 0 && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
                  <Clock className="w-4 h-4 text-cyan-400" />
                  <span>MTA Hop Traversal Sequence ({result.forensic_hops.length} Hops)</span>
                </h3>
                <span className="text-[10px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded font-mono font-semibold">
                  FACT: CHRONOLOGICAL RELAYS
                </span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                      <th className="py-2 px-3">Hop</th>
                      <th className="py-2 px-3">Relay IP</th>
                      <th className="py-2 px-3">Transferred From</th>
                      <th className="py-2 px-3">Received By</th>
                      <th className="py-2 px-3">Timestamp</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-300 text-[11px]">
                    {result.forensic_hops.map((h, hIdx) => (
                      <tr key={hIdx} className="hover:bg-slate-800/30">
                        <td className="py-2.5 px-3 font-bold text-cyan-400">#{h.hop_order}</td>
                        <td className="py-2.5 px-3 text-cyan-300">{h.relay_ip}</td>
                        <td className="py-2.5 px-3">{h.from_host}</td>
                        <td className="py-2.5 px-3">{h.by_host}</td>
                        <td className="py-2.5 px-3 text-slate-400">{h.raw_timestamp}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
