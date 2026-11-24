import React from 'react';

export default function ThreatBadge({ category }) {
  const cat = category || 'benign';
  const formatName = cat.replace(/_/g, ' ').toUpperCase();

  return (
    <span className="badge badge-threat">
      {formatName}
    </span>
  );
}
