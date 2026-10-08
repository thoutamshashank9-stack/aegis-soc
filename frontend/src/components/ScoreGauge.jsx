import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, AlertOctagon } from 'lucide-react';

export function ScoreGauge({ score = 0, level = 'LOW', size = 'lg' }) {
  // Score colors: Green (0-29), Yellow (30-59), Orange (60-79), Red (80-100)
  const getColor = (s) => {
    if (s >= 80) return { text: 'text-red-400', border: 'border-red-500', bg: 'bg-red-500/10', bar: 'bg-red-500' };
    if (s >= 60) return { text: 'text-orange-400', border: 'border-orange-500', bg: 'bg-orange-500/10', bar: 'bg-orange-500' };
    if (s >= 30) return { text: 'text-yellow-400', border: 'border-yellow-500', bg: 'bg-yellow-500/10', bar: 'bg-yellow-500' };
    return { text: 'text-emerald-400', border: 'border-emerald-500', bg: 'bg-emerald-500/10', bar: 'bg-emerald-500' };
  };

  const style = getColor(score);

  return (
    <div className={`flex flex-col items-center justify-center p-6 rounded-xl border ${style.border}/30 ${style.bg} relative overflow-hidden`}>
      <div className="flex items-center space-x-2 mb-2">
        {score >= 80 ? (
          <AlertOctagon className={`w-6 h-6 ${style.text}`} />
        ) : score >= 60 ? (
          <ShieldAlert className={`w-6 h-6 ${style.text}`} />
        ) : score >= 30 ? (
          <AlertTriangle className={`w-6 h-6 ${style.text}`} />
        ) : (
          <ShieldCheck className={`w-6 h-6 ${style.text}`} />
        )}
        <span className={`text-xs font-bold tracking-wider uppercase ${style.text}`}>
          THREAT LEVEL: {level}
        </span>
      </div>

      <div className="flex items-baseline space-x-1 my-1">
        <span className={`text-5xl font-black tracking-tight ${style.text}`}>{score}</span>
        <span className="text-slate-400 text-sm font-semibold">/100</span>
      </div>

      {/* Progress Bar */}
      <div className="w-full bg-slate-800 rounded-full h-2 mt-4 overflow-hidden border border-slate-700/60">
        <div
          className={`h-full ${style.bar} transition-all duration-700 rounded-full`}
          style={{ width: `${Math.min(100, Math.max(0, score))}%` }}
        />
      </div>

      <div className="flex justify-between w-full text-[10px] text-slate-400 mt-1.5 px-0.5">
        <span>0 (CLEAN)</span>
        <span>30</span>
        <span>60</span>
        <span>100 (CRITICAL)</span>
      </div>
    </div>
  );
}

export function SeverityBadge({ severity = 'low' }) {
  const sev = (severity || '').toLowerCase();
  if (sev === 'critical') {
    return <span className="px-2 py-0.5 text-[11px] font-bold rounded bg-red-950 text-red-300 border border-red-700/60 uppercase">CRITICAL</span>;
  }
  if (sev === 'high') {
    return <span className="px-2 py-0.5 text-[11px] font-bold rounded bg-orange-950 text-orange-300 border border-orange-700/60 uppercase">HIGH</span>;
  }
  if (sev === 'medium') {
    return <span className="px-2 py-0.5 text-[11px] font-bold rounded bg-yellow-950 text-yellow-300 border border-yellow-700/60 uppercase">MEDIUM</span>;
  }
  return <span className="px-2 py-0.5 text-[11px] font-bold rounded bg-emerald-950 text-emerald-300 border border-emerald-700/60 uppercase">LOW</span>;
}

export function AuthBadge({ protocol = 'SPF', status = 'unknown' }) {
  const st = (status || '').toLowerCase();
  const isPass = st === 'pass';
  const isFail = ['fail', 'softfail', 'reject', 'permerror'].includes(st);

  return (
    <div className={`p-3 rounded-lg border ${
      isPass ? 'bg-emerald-950/30 border-emerald-500/40' :
      isFail ? 'bg-red-950/30 border-red-500/40' :
      'bg-slate-800/40 border-slate-700/60'
    } flex items-center justify-between`}>
      <span className="text-xs font-semibold text-slate-300">{protocol}</span>
      <span className={`text-xs font-bold uppercase ${
        isPass ? 'text-emerald-400' :
        isFail ? 'text-red-400' :
        'text-slate-400'
      }`}>
        {status}
      </span>
    </div>
  );
}
