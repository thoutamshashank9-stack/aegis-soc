import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { 
  ShieldAlert, 
  Mail, 
  AlertTriangle, 
  Crosshair, 
  FileCheck, 
  ArrowRight,
  TrendingUp,
  Cpu,
  Layers
} from 'lucide-react';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell 
} from 'recharts';
import { api } from '../services/api';
import { SeverityBadge } from '../components/ScoreGauge';

export default function Dashboard() {
  const [analyses, setAnalyses] = useState([]);
  const [stats, setStats] = useState({
    total_ingested: 0,
    critical_threats: 0,
    high_risk: 0,
    medium_risk: 0,
    low_risk: 0,
    phishing_detections: 0,
    spam_detections: 0,
    legitimate_emails: 0,
  });
  const [systemStatus, setSystemStatus] = useState(null);
  const [mlStatus, setMLStatus] = useState(null);
  const [loading, setLoading] = useState(true);

  const [error, setError] = useState(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const results = await Promise.allSettled([
        api.getAnalyses(),
        api.getDashboardStats(),
        api.getSystemStatus(),
        api.getMLStatus(),
      ]);

      if (results[0].status === 'fulfilled') setAnalyses(results[0].value || []);
      if (results[1].status === 'fulfilled') setStats(results[1].value || {});
      if (results[2].status === 'fulfilled') setSystemStatus(results[2].value);
      if (results[3].status === 'fulfilled') setMLStatus(results[3].value);

      // If all failed, record error
      if (results.every((r) => r.status === 'rejected')) {
        setError('Unable to reach the threat intelligence backend service. Ensure the server is running.');
      }
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
      setError(err.message || 'An unexpected error occurred while loading dashboard telemetry.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  // Compute metrics dynamically from database aggregate response
  const total = stats.total_ingested;
  const criticalCount = stats.critical_threats;
  const highCount = stats.high_risk;
  const phishCount = stats.phishing_detections;

  // Chart data
  const threatDistData = [
    { name: 'Critical', count: criticalCount, color: '#ef4444' },
    { name: 'High', count: highCount, color: '#f97316' },
    { name: 'Medium', count: stats.medium_risk, color: '#eab308' },
    { name: 'Low', count: stats.low_risk, color: '#10b981' },
  ];

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Hero / Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <h1 className="text-2xl font-black text-slate-100 tracking-tight flex items-center space-x-3">
            <span>SOC Incident Operations & Threat Intelligence</span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Real-time multi-vector email threat classification, forensic timeline inspection & approximate IP geolocation.
          </p>
        </div>
        <Link
          to="/analyze"
          className="inline-flex items-center space-x-2 px-5 py-2.5 bg-red-600 hover:bg-red-500 text-white rounded-lg font-medium text-sm transition-all shadow-lg shadow-red-950/50"
        >
          <ShieldAlert className="w-4 h-4" />
          <span>Launch Threat Sandbox</span>
        </Link>
      </div>

      {/* KPI Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl shadow-sm">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Total Ingested</span>
            <Mail className="w-5 h-5 text-indigo-400" />
          </div>
          <p className="text-3xl font-black text-slate-100 mt-2">{total}</p>
          <p className="text-xs text-slate-400 mt-1 flex items-center space-x-1">
            <span>Historical investigations stored</span>
          </p>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl shadow-sm">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Critical Threats</span>
            <ShieldAlert className="w-5 h-5 text-red-500" />
          </div>
          <p className="text-3xl font-black text-red-400 mt-2">{criticalCount}</p>
          <p className="text-xs text-slate-400 mt-1">Score ≥ 80 / 100 severity</p>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl shadow-sm">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">High Risk Inbounds</span>
            <AlertTriangle className="w-5 h-5 text-orange-400" />
          </div>
          <p className="text-3xl font-black text-orange-400 mt-2">{highCount}</p>
          <p className="text-xs text-slate-400 mt-1">Score 60 - 79 severity</p>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl shadow-sm">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Phishing Detections</span>
            <Crosshair className="w-5 h-5 text-cyan-400" />
          </div>
          <p className="text-3xl font-black text-cyan-300 mt-2">{phishCount}</p>
          <p className="text-xs text-slate-400 mt-1">Classified by NLP ML Pipeline</p>
        </div>
      </div>

      {/* Visual Analytics Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Distribution Chart */}
        <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl lg:col-span-1">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300 mb-4 flex items-center space-x-2">
            <TrendingUp className="w-4 h-4 text-slate-400" />
            <span>Threat Severity Distribution</span>
          </h2>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={threatDistData}
                  dataKey="count"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={70}
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                >
                  {threatDistData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#fff' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Engine Pipeline Architecture Status */}
        <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl lg:col-span-2">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300 mb-4 flex items-center space-x-2">
            <Layers className="w-4 h-4 text-slate-400" />
            <span>Integrated Forensic Defense Stack</span>
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
              <span className="text-xs text-slate-400 font-semibold uppercase">RFC 5322 Ingestion</span>
              <p className="text-sm font-bold text-slate-200 mt-1">email.parser & Safe MIME</p>
              <p className="text-xs text-slate-400 mt-1">Deterministic header extraction & boundary splitting</p>
            </div>

            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
              <span className="text-xs text-slate-400 font-semibold uppercase">Authentication Engine</span>
              <p className="text-sm font-bold text-slate-200 mt-1">SPF, DKIM & DMARC Align</p>
              <p className="text-xs text-slate-400 mt-1">Cross-correlates Return-Path, From, and Auth records</p>
            </div>

            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
              <span className="text-xs text-slate-400 font-semibold uppercase">Supervised ML</span>
              <p className="text-sm font-bold text-slate-200 mt-1">TF-IDF + Logistic Regression</p>
              <p className="text-xs text-slate-400 mt-1">Evaluated on real n-gram text representation</p>
            </div>

            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
              <span className="text-xs text-slate-400 font-semibold uppercase">Routing Forensics</span>
              <p className="text-sm font-bold text-slate-200 mt-1">MTA Chain & Geolocation</p>
              <p className="text-xs text-slate-400 mt-1">Chronological hops and approximate public IP geolocation</p>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Investigations Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200">
            Recent Forensic Ingestions
          </h2>
          <Link to="/analyze" className="text-xs text-red-400 hover:text-red-300 font-medium flex items-center space-x-1">
            <span>Analyze New Email</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        {analyses.length === 0 ? (
          <div className="p-8 text-center text-slate-400">
            <Mail className="w-8 h-8 mx-auto mb-2 opacity-50" />
            <p>No email investigations conducted yet.</p>
            <p className="text-xs text-slate-400 mt-1">Upload an .eml sample or paste email headers in the Threat Sandbox.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950/80 text-slate-400 uppercase font-semibold border-b border-slate-800">
                <tr>
                  <th className="px-5 py-3.5">Filename / Subject</th>
                  <th className="px-5 py-3.5">Claimed Sender</th>
                  <th className="px-5 py-3.5">ML Classification</th>
                  <th className="px-5 py-3.5">Threat Level</th>
                  <th className="px-5 py-3.5">Risk Score</th>
                  <th className="px-5 py-3.5 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {analyses.slice(0, 8).map((item) => (
                  <tr key={item.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-5 py-3.5 font-medium text-slate-200 max-w-xs truncate">
                      <div>{item.subject || '(No Subject)'}</div>
                      <div className="text-[10px] text-slate-400">{item.filename}</div>
                    </td>
                    <td className="px-5 py-3.5 max-w-xs truncate text-slate-300 font-mono text-[11px]">
                      {item.sender_email}
                    </td>
                    <td className="px-5 py-3.5">
                      <span className="capitalize font-semibold text-slate-300">{item.ml_prediction}</span>
                    </td>
                    <td className="px-5 py-3.5">
                      <SeverityBadge severity={item.risk_level} />
                    </td>
                    <td className="px-5 py-3.5 font-black text-slate-100">
                      {item.risk_score}/100
                    </td>
                    <td className="px-5 py-3.5 text-right">
                      <Link
                        to={`/forensics?id=${item.id}`}
                        className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded border border-slate-700 transition"
                      >
                        Inspect
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
