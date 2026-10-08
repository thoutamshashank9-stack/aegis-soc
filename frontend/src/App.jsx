import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import EmailAnalyzerPage from './pages/EmailAnalyzerPage';
import GeolocationPage from './pages/GeolocationPage';
import ForensicsPage from './pages/ForensicsPage';
import IOCsPage from './pages/IOCsPage';
import ReportsPage from './pages/ReportsPage';
import MLStatusPage from './pages/MLStatusPage';

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-red-500/30 selection:text-white">
        {/* Navigation Sidebar */}
        <Sidebar />

        {/* Dynamic Page Container */}
        <main className="flex-1 overflow-y-auto bg-[#0b0f19]">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/analyze" element={<EmailAnalyzerPage />} />
            <Route path="/geo" element={<GeolocationPage />} />
            <Route path="/forensics" element={<ForensicsPage />} />
            <Route path="/iocs" element={<IOCsPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/ml-status" element={<MLStatusPage />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
