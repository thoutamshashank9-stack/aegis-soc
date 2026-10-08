import React, { useEffect, useState } from 'react';
import { Crosshair, Download, Copy, Check, ShieldAlert } from 'lucide-react';
import { api } from '../services/api';

export default function IOCsPage() {
  const [analyses, setAnalyses] = useState([]);
  const [selectedId, setSelectedId] = useState('');
  const [iocData, setIOCData] = useState(null);
  const [copiedKey, setCopiedKey] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        const list = await api.getAnalyses();
        setAnalyses(list);
        if (list.length > 0) {
          setSelectedId(list[0].id);
          const iocs = await api.getIOCs(list[0].id);
          setIOCData(iocs);
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
      const iocs = await api.getIOCs(id);
      setIOCData(iocs);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const exportJSON = () => {
    if (!iocData) return;
    const blob = new Blob([JSON.stringify(iocData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `IOCs_${selectedId.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const indicators = iocData?.indicators || {};

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Title */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-2xl font-black text-slate-100 tracking-tight flex items-center space-x-3">
            <Crosshair className="w-6 h-6 text-red-400" />
            <span>Indicators of Compromise (IOC) Explorer</span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Standardized threat intelligence artifacts formatted for SIEM ingestion, firewall blocking, and threat hunting.
          </p>
        </div>
        <button
          onClick={exportJSON}
          disabled={!iocData}
          className="inline-flex items-center space-x-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold transition"
        >
          <Download className="w-4 h-4 text-slate-400" />
          <span>Export IOC Package (JSON)</span>
        </button>
      </div>

      {/* Selector */}
      <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          Target Investigation:
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

      {/* IOC Category Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {Object.entries(indicators).map(([category, items]) => (
          <div key={category} className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <span className="font-bold text-xs uppercase tracking-wider text-slate-300">
                {category} Indicators ({items.length})
              </span>
              <button
                onClick={() => copyToClipboard(items.join('\n'), category)}
                className="text-[11px] text-slate-400 hover:text-slate-200 flex items-center space-x-1"
              >
                {copiedKey === category ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-400" />
                    <span className="text-emerald-400">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span>Copy All</span>
                  </>
                )}
              </button>
            </div>

            <div className="max-h-56 overflow-y-auto space-y-1.5">
              {items.map((val, idx) => (
                <div
                  key={idx}
                  className="p-2 bg-slate-950 rounded font-mono text-xs text-cyan-300 border border-slate-800/80 flex items-center justify-between break-all"
                >
                  <span>{val}</span>
                  <button
                    onClick={() => copyToClipboard(val, `${category}-${idx}`)}
                    className="ml-2 text-slate-400 hover:text-slate-300"
                  >
                    {copiedKey === `${category}-${idx}` ? (
                      <Check className="w-3 h-3 text-emerald-400" />
                    ) : (
                      <Copy className="w-3 h-3" />
                    )}
                  </button>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
