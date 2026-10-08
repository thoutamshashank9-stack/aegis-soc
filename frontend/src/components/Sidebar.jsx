import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  ShieldAlert, 
  LayoutDashboard, 
  MailSearch, 
  MapPin, 
  FileText, 
  Crosshair, 
  Activity,
  Cpu
} from 'lucide-react';

export default function Sidebar() {
  const links = [
    { to: '/', label: 'Overview', icon: LayoutDashboard },
    { to: '/analyze', label: 'Email Threat Sandbox', icon: MailSearch },
    { to: '/geo', label: 'IP Geolocation & Maps', icon: MapPin },
    { to: '/forensics', label: 'Forensic Timelines', icon: Activity },
    { to: '/iocs', label: 'IOC Threat Intelligence', icon: Crosshair },
    { to: '/reports', label: 'Executive Reports', icon: FileText },
    { to: '/ml-status', label: 'ML Model Insights', icon: Cpu },
  ];

  return (
    <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col shrink-0 min-h-screen">
      {/* Brand Header */}
      <div className="p-5 border-b border-slate-800 flex items-center space-x-3">
        <div className="p-2 bg-red-950/80 border border-red-500/40 rounded-lg text-red-400">
          <ShieldAlert className="w-6 h-6" />
        </div>
        <div>
          <h1 className="text-sm font-bold tracking-wider text-slate-100 uppercase">AegisSOC</h1>
          <p className="text-xs text-slate-400">Threat Intelligence</p>
        </div>
      </div>

      {/* Nav Menu */}
      <nav className="flex-1 p-4 space-y-1.5">
        <div className="text-[10px] font-semibold tracking-wider text-slate-400 uppercase px-3 py-1">
          SOC Investigations
        </div>
        {links.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-red-900/30 text-red-300 border border-red-600/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`
              }
            >
              <Icon className="w-4 h-4" />
              <span>{item.label}</span>
            </NavLink>
          );
        })}
      </nav>

      {/* Operational Status Footer */}
      <div className="p-4 border-t border-slate-800 text-xs">
        <div className="flex items-center justify-between text-slate-400 mb-2">
          <span className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>MTA Pipeline Active</span>
          </span>
          <span className="text-[10px] bg-slate-800 px-1.5 py-0.5 rounded border border-slate-700">v1.0</span>
        </div>
        <p className="text-[11px] text-slate-400 leading-tight">
          Hybrid Rules + TF-IDF ML + Geolocation Forensics
        </p>
      </div>
    </aside>
  );
}
