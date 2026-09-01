import React, { useState } from 'react';
import { Sidebar, PageId } from '../components/Sidebar';
import { Header } from '../components/Header';
import { Dashboard } from '../pages/Dashboard';
import { Devices } from '../pages/Devices';
import { Sanitization } from '../pages/Sanitization';
import { ForensicRecovery } from '../pages/ForensicRecovery';
import { Verification } from '../pages/Verification';
import { AuditTrail } from '../pages/AuditTrail';
import { Reports } from '../pages/Reports';
import { Laboratory } from '../pages/Laboratory';

export const App: React.FC = () => {
  const [activePage, setActivePage] = useState<PageId>('dashboard');

  const pageHeaders: Record<PageId, { title: string; subtitle: string }> = {
    dashboard: {
      title: 'Operational Dashboard',
      subtitle: 'Overview of storage devices, safety gates, and forensic verification',
    },
    devices: {
      title: 'Device & Bus Manager',
      subtitle: 'Enumerated hardware targets and media classification',
    },
    sanitization: {
      title: 'Capability-Aware Sanitization',
      subtitle: 'NIST / DoD / IEEE standard policy execution',
    },
    forensics: {
      title: 'Forensic Acquisition & Carving',
      subtitle: 'Read-only deep artifact recovery and graph reconstruction',
    },
    verification: {
      title: 'L1–L4 Multi-Level Verification',
      subtitle: 'Cryptographic proof and post-sanitization validation',
    },
    audit: {
      title: 'Tamper-Evident Audit Trail',
      subtitle: 'SHA-256 hash-chained event logs',
    },
    reports: {
      title: 'Compliance Reports & Attestation',
      subtitle: 'Digital certificate export and signed results',
    },
    lab: {
      title: 'Virtual Forensic Lab',
      subtitle: 'Synthetic disk fixtures and hardware simulation sandbox',
    },
  };

  const renderPage = () => {
    switch (activePage) {
      case 'dashboard':
        return <Dashboard onNavigate={setActivePage} />;
      case 'devices':
        return <Devices />;
      case 'sanitization':
        return <Sanitization />;
      case 'forensics':
        return <ForensicRecovery />;
      case 'verification':
        return <Verification />;
      case 'audit':
        return <AuditTrail />;
      case 'reports':
        return <Reports />;
      case 'lab':
        return <Laboratory />;
      default:
        return <Dashboard onNavigate={setActivePage} />;
    }
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-background">
      <Sidebar activePage={activePage} onSelectPage={setActivePage} />
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Header
          title={pageHeaders[activePage].title}
          subtitle={pageHeaders[activePage].subtitle}
        />
        <main className="flex-1 overflow-y-auto">
          {renderPage()}
        </main>
      </div>
    </div>
  );
};

export default App;
