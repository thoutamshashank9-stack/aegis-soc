import React, { useEffect, useState } from 'react';
import { Activity, Clock, Server, ArrowDown, Shield, FileCode, CheckCircle2 } from 'lucide-react';
import { api } from '../services/api';

export default function ForensicsPage() {
  const [analyses, setAnalyses] = useState([]);
  const [selectedAnalysis, setSelectedAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check url search params for ?id=
    const params = new URLSearchParams(window.location.search);
    const targetId = params.get('id');

    async function loadData() {
      try {
        const list = await api.getAnalyses();
        setAnalyses(list);
        if (list.length > 0) {
          const idToLoad = targetId && list.some(l => l.id === targetId) ? targetId : list[0].id;
          const detail = await api.getAnalysis(idToLoad);
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

  const hops = selectedAnalysis?.forensic_hops || [];

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Title */}
      <div className="border-b border-slate-800 pb-5">
        <h1 className="text-2xl font-black text-slate-100 tracking-tight flex items-center space-x-3">
          <Activity className="w-6 h-6 text-indigo-400" />
          <span>MTA Header Chain & Forensic Timeline</span>
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Chronological hop-by-hop relay traversal reconstructed strictly from verified Received headers.
        </p>
      </div>

      {/* Selector */}
      <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          Selected Investigation:
        </span>
        <select
          onChange={(e) => handleSelect(e.target.value)}
          value={selectedAnalysis?.id || ''}
          className="bg-slate-950 border border-slate-700 text-xs text-slate-200 rounded-lg px-3 py-1.5 focus:outline-none font-mono"
        >
          {analyses.map((a) => (
            <option key={a.id} value={a.id}>
              {a.filename} ({a.risk_level})
            </option>
          ))}
        </select>
      </div>

      {/* Forensic Overview Details */}
      {selectedAnalysis && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 grid grid-cols-1 md:grid-cols-3 gap-6 text-xs">
          <div>
            <span className="text-slate-400 block uppercase font-bold text-[10px]">Message Identification</span>
            <p className="font-mono text-slate-200 mt-1 break-all">{selectedAnalysis.message_id || 'N/A'}</p>
          </div>
          <div>
            <span className="text-slate-400 block uppercase font-bold text-[10px]">SHA-256 Cryptographic Hash</span>
            <p className="font-mono text-cyan-300 mt-1 break-all">{selectedAnalysis.sha256}</p>
          </div>
          <div>
            <span className="text-slate-400 block uppercase font-bold text-[10px]">Transmission Dates</span>
            <p className="font-mono text-slate-200 mt-1">{selectedAnalysis.date || 'Recorded'}</p>
          </div>
        </div>
      )}

      {/* MTA Chronological Relay Chain */}
      <div className="space-y-4">
        <h2 className="text-xs font-bold uppercase tracking-wider text-slate-400">
          Chronological MTA Relay Chain ({hops.length} Hops Detected)
        </h2>

        {hops.length === 0 ? (
          <div className="p-10 bg-slate-900 border border-slate-800 rounded-xl text-center text-xs text-slate-400">
            No RFC Received headers found in this message.
          </div>
        ) : (
          <div className="space-y-3 relative">
            {hops.map((hop, idx) => (
              <div key={idx} className="relative flex items-start space-x-4">
                {/* Node icon & connection line */}
                <div className="flex flex-col items-center">
                  <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center font-bold text-xs text-cyan-400">
                    {hop.hop_order}
                  </div>
                  {idx < hops.length - 1 && (
                    <div className="w-0.5 h-12 bg-slate-800 my-1" />
                  )}
                </div>

                {/* Hop card */}
                <div className="flex-1 bg-slate-900 border border-slate-800 rounded-xl p-4 text-xs space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-200">
                      Hop #{hop.hop_order}: {hop.from_host} → {hop.by_host}
                    </span>
                    <span className="font-mono text-[11px] text-cyan-400 bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-800/30">
                      Relay IP: {hop.relay_ip}
                    </span>
                  </div>

                  <div className="text-slate-400 flex items-center space-x-2">
                    <Clock className="w-3.5 h-3.5" />
                    <span className="font-mono text-[11px]">{hop.raw_timestamp}</span>
                  </div>

                  {hop.raw_header_snippet && (
                    <div className="bg-slate-950 p-2.5 rounded font-mono text-[10px] text-slate-400 break-all border border-slate-800/60">
                      {hop.raw_header_snippet}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
