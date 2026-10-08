import React, { useEffect, useState } from 'react';
import { FileText, Printer, Download, ShieldAlert, CheckCircle2, AlertOctagon } from 'lucide-react';
import { api } from '../services/api';
import { SeverityBadge } from '../components/ScoreGauge';

export default function ReportsPage() {
  const [analyses, setAnalyses] = useState([]);
  const [selectedId, setSelectedId] = useState('');
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        const list = await api.getAnalyses();
        setAnalyses(list);
        if (list.length > 0) {
          setSelectedId(list[0].id);
          const rep = await api.getReport(list[0].id);
          setReport(rep);
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
    setSelectedId(id);
    setLoading(true);
    try {
      const rep = await api.getReport(id);
      setReport(rep);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handlePrint = () => {
    window.print();
  };

  const exportJSON = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Forensic_Report_${selectedId.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-8 space-y-8 max-w-5xl mx-auto">
      {/* Title & Actions */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5 print:hidden">
        <div>
          <h1 className="text-2xl font-black text-slate-100 tracking-tight flex items-center space-x-3">
            <FileText className="w-6 h-6 text-emerald-400" />
            <span>Executive Forensic & Security Intelligence Reports</span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Printable audit reports summarizing technical evidence, verdicts, indicators & forensic chain.
          </p>
        </div>
        <div className="flex space-x-3">
          <button
            onClick={exportJSON}
            disabled={!report}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition"
          >
            <Download className="w-4 h-4 text-slate-400" />
            <span>Export JSON</span>
          </button>
          <button
            onClick={handlePrint}
            disabled={!report}
            className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition shadow"
          >
            <Printer className="w-4 h-4" />
            <span>Print / Save PDF</span>
          </button>
        </div>
      </div>

      {/* Selector */}
      <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex items-center justify-between print:hidden">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          Select Investigation to Inspect:
        </span>
        <select
          onChange={(e) => handleSelect(e.target.value)}
          value={selectedId}
          className="bg-slate-950 border border-slate-700 text-xs text-slate-200 rounded-lg px-3 py-1.5 focus:outline-none font-mono"
        >
          {analyses.map((a) => (
            <option key={a.id} value={a.id}>
              {a.filename} ({a.risk_level})
            </option>
          ))}
        </select>
      </div>

      {/* Printable Report Sheet */}
      {report && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 space-y-6 text-slate-200 print:bg-white print:text-black print:border-none print:p-0">
          {/* Header */}
          <div className="border-b border-slate-800 pb-5 flex items-start justify-between">
            <div>
              <span className="text-[10px] font-bold uppercase tracking-widest text-red-400 block">
                SOC THREAT INTELLIGENCE AUDIT RECORD
              </span>
              <h2 className="text-xl font-black mt-1">{report.title}</h2>
              <p className="text-xs text-slate-400 mt-1 font-mono">
                Report ID: {report.report_id} | Timestamp: {report.generated_at}
              </p>
            </div>
            <div className="text-right">
              <span className="text-xs uppercase font-bold text-slate-400 block">Verdict Severity</span>
              <span className="text-2xl font-black text-red-400">{report.verdict.risk_score} / 100</span>
            </div>
          </div>

          {/* Evidence Integrity */}
          <div className="bg-slate-950/60 p-4 rounded-xl border border-slate-800 space-y-1.5 text-xs font-mono">
            <div className="text-slate-400 font-sans uppercase font-bold text-[10px]">Evidence Artifact Integrity:</div>
            <div>File Name: {report.evidence_integrity.filename}</div>
            <div className="text-cyan-300 break-all">SHA-256: {report.evidence_integrity.sha256}</div>
            <div>Size: {report.evidence_integrity.size_bytes} bytes</div>
          </div>

          {/* Executive Summary */}
          <div className="space-y-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">
              Executive Evaluation Summary
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed bg-slate-950/40 p-4 rounded-xl border border-slate-800">
              {report.verdict.executive_summary}
            </p>
          </div>

          {/* Sender & Envelope */}
          <div className="space-y-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">
              Sender & Envelope Attribution
            </h3>
            <div className="grid grid-cols-2 gap-3 text-xs bg-slate-950/40 p-4 rounded-xl border border-slate-800">
              <div>
                <span className="text-slate-400 block text-[10px] uppercase">Claimed From</span>
                <span className="font-mono text-slate-200">{report.sender_metadata.claimed_sender}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[10px] uppercase">Recipient</span>
                <span className="font-mono text-slate-200">{report.sender_metadata.recipient}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[10px] uppercase">Reply-To</span>
                <span className="font-mono text-slate-200">{report.sender_metadata.reply_to || 'None'}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[10px] uppercase">Return-Path</span>
                <span className="font-mono text-slate-200">{report.sender_metadata.return_path || 'None'}</span>
              </div>
            </div>
          </div>

          {/* Cryptographic Authentication */}
          {report.authentication && (
            <div className="space-y-2">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                Cryptographic Authentication Posture
              </h3>
              <div className="grid grid-cols-3 gap-3 text-xs bg-slate-950/40 p-4 rounded-xl border border-slate-800">
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">SPF Record</span>
                  <span className="font-mono font-bold uppercase text-cyan-300">{report.authentication.spf || 'UNKNOWN'}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">DKIM Signature</span>
                  <span className="font-mono font-bold uppercase text-cyan-300">{report.authentication.dkim || 'UNKNOWN'}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase">DMARC Policy</span>
                  <span className="font-mono font-bold uppercase text-cyan-300">{report.authentication.dmarc || 'UNKNOWN'}</span>
                </div>
              </div>
            </div>
          )}

          {/* Key Threat Indicators */}
          <div className="space-y-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">
              Key Observed Security Indicators ({report.key_threat_indicators.length})
            </h3>
            <div className="space-y-2">
              {report.key_threat_indicators.map((ind, i) => (
                <div key={i} className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg text-xs space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-200">{ind.indicator}</span>
                    <SeverityBadge severity={ind.severity} />
                  </div>
                  <p className="text-slate-400">{ind.reason}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Limitations Notice */}
          <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 text-[11px] text-slate-400 space-y-1">
            <div className="font-bold uppercase tracking-wider text-slate-300">Forensic Limitations:</div>
            {report.limitations_notice.map((lim, i) => (
              <p key={i}>• {lim}</p>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
