import React from 'react';
import { CheckCircle2, AlertTriangle, ShieldX } from 'lucide-react';

export default function DecisionBadge({ action }) {
  const act = (action || 'PASS').toUpperCase();

  if (act === 'PASS') {
    return (
      <span className="badge badge-pass">
        <CheckCircle2 size={13} /> PASS
      </span>
    );
  }
  if (act === 'SANITIZE' || act === 'QUARANTINE') {
    return (
      <span className="badge badge-sanitize">
        <AlertTriangle size={13} /> {act}
      </span>
    );
  }
  return (
    <span className="badge badge-block">
      <ShieldX size={13} /> BLOCK
    </span>
  );
}
