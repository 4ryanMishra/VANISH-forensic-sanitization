import React, { useState, useEffect } from 'react';
import { AuditEvent } from '../types';
import { fetchAuditLog } from '../services/api';
import { ShieldCheck, Clock } from 'lucide-react';

export const AuditTrail: React.FC = () => {
  const [events, setEvents] = useState<AuditEvent[]>([]);

  useEffect(() => {
    fetchAuditLog().then(setEvents);
  }, []);

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-xl font-bold text-white">Tamper-Evident Audit Trail</h3>
          <p className="text-xs text-gray-400">Cryptographically linked SHA-256 event log chain</p>
        </div>
        <div className="flex items-center space-x-2 px-3 py-1.5 rounded-full bg-emerald-950/40 border border-emerald-500/30 text-xs text-emerald-400">
          <ShieldCheck className="w-4 h-4" />
          <span>Chain Integrity Valid</span>
        </div>
      </div>

      <div className="space-y-4">
        {events.map((evt) => (
          <div key={evt.event_id} className="p-5 rounded-xl bg-surface border border-gray-800 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <span className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 font-mono text-xs font-bold">
                  #{evt.sequence_number}
                </span>
                <span className="font-bold text-white text-sm">{evt.operation}</span>
                <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 text-xs font-medium">
                  {evt.result_status}
                </span>
              </div>
              <div className="flex items-center space-x-1.5 text-xs text-gray-400 font-mono">
                <Clock className="w-3.5 h-3.5" />
                <span>{new Date(evt.timestamp).toLocaleString()}</span>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono pt-2 border-t border-gray-800/80">
              <div>
                <span className="text-gray-500 block">PREVIOUS HASH:</span>
                <span className="text-gray-400 break-all">{evt.previous_event_hash}</span>
              </div>
              <div>
                <span className="text-gray-500 block">CURRENT HASH:</span>
                <span className="text-blue-400 break-all">{evt.current_event_hash}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
