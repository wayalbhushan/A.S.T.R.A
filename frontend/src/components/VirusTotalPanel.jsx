export default function VirusTotalPanel({ result }) {
  const status = result?.vt_status || result?.vt_data?.status
  const intel = result?.vt_intel || result?.vt_data?.intel
  const detectionRatio = result?.vt_detection_ratio || result?.vt_data?.detection_ratio

  if (!status && !intel) {
    return null
  }

  // Key/value grid rows for 'ok' status
  const gridRows = []
  if (detectionRatio) {
    gridRows.push(['Detections', detectionRatio])
  }
  if (intel?.first_submission_date) {
    gridRows.push(['First seen on VirusTotal', String(intel.first_submission_date).slice(0, 10)])
  }
  if (intel?.last_analysis_date) {
    gridRows.push(['Last analysed', String(intel.last_analysis_date).slice(0, 10)])
  }
  if (intel?.times_submitted !== undefined && intel?.times_submitted !== null) {
    gridRows.push(['Times submitted', String(intel.times_submitted)])
  }
  if (intel?.reputation !== undefined && intel?.reputation !== null) {
    gridRows.push(['Community reputation', String(intel.reputation)])
  }

  const hasAvailableFields = Boolean(intel && Array.isArray(intel.available_fields) && intel.available_fields.length > 0)

  return (
    <div style={{
      background: 'var(--bg-secondary)',
      border: '1px solid var(--border)',
      padding: '16px'
    }}>
      {/* Header row */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: '4px'
      }}>
        <div style={{
          fontSize: '12px',
          fontWeight: 600,
          letterSpacing: '0.32px',
          textTransform: 'uppercase',
          color: 'var(--text-primary)'
        }}>
          VIRUSTOTAL INTELLIGENCE
        </div>
        <div style={{
          background: 'var(--bg-elevated)',
          border: '1px solid var(--border)',
          fontSize: '10px',
          padding: '2px 6px',
          color: 'var(--text-secondary)',
          letterSpacing: '0.32px',
          textTransform: 'uppercase'
        }}>
          EXTERNAL, OPTIONAL
        </div>
      </div>

      {/* Subtitle */}
      <div style={{
        fontSize: '12px',
        color: 'var(--text-secondary)',
        marginBottom: '16px'
      }}>
        Context from VirusTotal. The detail fields below do not change the risk score.
      </div>

      {/* Status-specific rendering */}
      {status === 'not_found' && (
        <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
          VirusTotal has no record of this file.
        </div>
      )}

      {status === 'disabled' && (
        <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
          VirusTotal lookup is turned off for this deployment. ASTRA's own analysis was used.
        </div>
      )}

      {status === 'rate_limited' && (
        <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
          VirusTotal quota was reached. This scan finished without it.
        </div>
      )}

      {status === 'unavailable' && (
        <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
          VirusTotal could not be reached. This scan finished without it.
        </div>
      )}

      {status !== 'ok' && status !== 'not_found' && status !== 'disabled' && status !== 'rate_limited' && status !== 'unavailable' && (
        <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
          VirusTotal data is not available for this scan.
        </div>
      )}

      {status === 'ok' && (
        <div>
          {/* Key/value grid */}
          {gridRows.length > 0 && (
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
              gap: '12px',
              marginBottom: '16px',
              background: 'var(--bg-elevated)',
              padding: '12px 16px',
              border: '1px solid var(--border)'
            }}>
              {gridRows.map(([key, val]) => (
                <div key={key}>
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                    {key}
                  </div>
                  <div className="mono" style={{ fontSize: '13px', color: 'var(--text-primary)' }}>
                    {val}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Threat classification */}
          {intel?.threat && (
            <div style={{ marginBottom: '16px' }}>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                VirusTotal threat label
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                {intel.threat.label && (
                  <span className="mono" style={{ fontSize: '13px', fontWeight: 600, color: 'var(--danger)' }}>
                    {intel.threat.label}
                  </span>
                )}
                {intel.threat.category && (
                  <span style={{
                    fontSize: '11px',
                    background: 'var(--bg-elevated)',
                    border: '1px solid var(--border)',
                    padding: '2px 6px',
                    color: 'var(--text-primary)'
                  }}>
                    {intel.threat.category}
                  </span>
                )}
                {Array.isArray(intel.threat.names) && intel.threat.names.map((name, i) => (
                  <span key={i} style={{
                    fontSize: '11px',
                    background: 'var(--bg-elevated)',
                    border: '1px solid var(--border)',
                    padding: '2px 6px',
                    color: 'var(--text-primary)'
                  }}>
                    {name}
                  </span>
                ))}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-placeholder)', marginTop: '4px' }}>
                Label from VirusTotal engines, not an ASTRA finding.
              </div>
            </div>
          )}

          {/* File names seen */}
          {Array.isArray(intel?.names) && intel.names.length > 0 && (
            <div style={{ marginBottom: '16px' }}>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                File names seen
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                {intel.names.slice(0, 5).map((name, i) => (
                  <div key={i} className="mono" style={{ fontSize: '12px', color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                    {name}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Behaviour tags */}
          {Array.isArray(intel?.tags) && intel.tags.length > 0 && (
            <div style={{ marginBottom: '16px' }}>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                Behaviour tags
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginBottom: '4px' }}>
                {intel.tags.map((tag, i) => (
                  <span key={i} style={{
                    fontSize: '11px',
                    background: 'var(--bg-elevated)',
                    border: '1px solid var(--border)',
                    padding: '2px 6px',
                    color: 'var(--text-primary)'
                  }}>
                    {tag}
                  </span>
                ))}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-placeholder)' }}>
                Tags describe observed capabilities. Legitimate apps can carry them too.
              </div>
            </div>
          )}

          {/* Sandbox verdicts */}
          {Array.isArray(intel?.sandbox_verdicts) && intel.sandbox_verdicts.length > 0 && (
            <div style={{ marginBottom: '16px' }}>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                Sandbox verdicts
              </div>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                <thead>
                  <tr style={{ background: 'var(--bg-elevated)', borderBottom: '1px solid var(--border)' }}>
                    <th style={{ textAlign: 'left', padding: '6px 10px', color: 'var(--text-secondary)', fontWeight: 600 }}>Sandbox</th>
                    <th style={{ textAlign: 'left', padding: '6px 10px', color: 'var(--text-secondary)', fontWeight: 600 }}>Verdict</th>
                    <th style={{ textAlign: 'left', padding: '6px 10px', color: 'var(--text-secondary)', fontWeight: 600 }}>Confidence</th>
                    <th style={{ textAlign: 'left', padding: '6px 10px', color: 'var(--text-secondary)', fontWeight: 600 }}>Malware names</th>
                  </tr>
                </thead>
                <tbody>
                  {intel.sandbox_verdicts.map((v, i) => {
                    let verdictColor = 'var(--text-secondary)'
                    const cat = (v.category || '').toLowerCase()
                    if (cat === 'malicious') verdictColor = 'var(--danger)'
                    else if (cat === 'suspicious') verdictColor = 'var(--warning)'

                    return (
                      <tr key={i} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                        <td style={{ padding: '6px 10px', color: 'var(--text-primary)' }}>{v.sandbox}</td>
                        <td style={{ padding: '6px 10px', color: verdictColor, fontWeight: 600 }}>{v.category || 'unknown'}</td>
                        <td className="mono" style={{ padding: '6px 10px', color: 'var(--text-primary)' }}>
                          {v.confidence !== undefined && v.confidence !== null ? `${v.confidence}%` : '-'}
                        </td>
                        <td style={{ padding: '6px 10px', color: 'var(--text-primary)' }}>
                          {(Array.isArray(v.malware_names) && v.malware_names.length > 0) ? v.malware_names.join(', ') : '-'}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* YARA matches */}
          {Array.isArray(intel?.yara) && intel.yara.length > 0 && (
            <div style={{ marginBottom: '16px' }}>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                YARA matches
              </div>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                <thead>
                  <tr style={{ background: 'var(--bg-elevated)', borderBottom: '1px solid var(--border)' }}>
                    <th style={{ textAlign: 'left', padding: '6px 10px', color: 'var(--text-secondary)', fontWeight: 600 }}>Rule</th>
                    <th style={{ textAlign: 'left', padding: '6px 10px', color: 'var(--text-secondary)', fontWeight: 600 }}>Ruleset</th>
                    <th style={{ textAlign: 'left', padding: '6px 10px', color: 'var(--text-secondary)', fontWeight: 600 }}>Source</th>
                  </tr>
                </thead>
                <tbody>
                  {intel.yara.map((y, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                      <td className="mono" style={{ padding: '6px 10px', color: 'var(--text-primary)' }}>{y.rule || '-'}</td>
                      <td style={{ padding: '6px 10px', color: 'var(--text-secondary)' }}>{y.ruleset || '-'}</td>
                      <td style={{ padding: '6px 10px', color: 'var(--text-secondary)', wordBreak: 'break-all' }}>
                        {(y.source || '').slice(0, 60)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Empty details fallback */}
          {!hasAvailableFields && (
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '8px' }}>
              VirusTotal returned no extra details for this file.
            </div>
          )}
        </div>
      )}
    </div>
  )
}
