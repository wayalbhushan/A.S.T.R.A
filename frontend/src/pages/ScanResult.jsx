import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  ArrowLeft, AlertTriangle, Shield,
  Cpu, Globe, Lock, FileText, Download, Copy, Check
} from 'lucide-react'
import { api } from '../api/client'
import VerdictBadge from '../components/VerdictBadge'
import RiskScore from '../components/RiskScore'

export default function ScanResult() {
  const { scanId } = useParams()
  const navigate = useNavigate()
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [copiedKey, setCopiedKey] = useState(null)

  const copyToClipboard = (text, key) => {
    if (!text) return
    navigator.clipboard.writeText(text)
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  const exportReportJSON = () => {
    if (!result) return
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(result, null, 2))
    const downloadAnchor = document.createElement('a')
    downloadAnchor.setAttribute("href", dataStr)
    downloadAnchor.setAttribute("download", `astra_scan_${scanId}_report.json`)
    document.body.appendChild(downloadAnchor)
    downloadAnchor.click()
    downloadAnchor.remove()
  }

  useEffect(() => {
    api.getScanResult(scanId)
      .then(res => setResult(res.data.data))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [scanId])

  if (loading) return (
    <div style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>
      Loading result...
    </div>
  )

  if (error) return (
    <div style={{ color: 'var(--danger)', fontSize: '14px' }}>
      Error: {error}
    </div>
  )

  if (!result) return (
    <div style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>
      No result found.
    </div>
  )

  if (result.status === 'pending' || result.status === 'processing') {
    return (
      <div style={{
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border)',
        padding: '24px',
        color: 'var(--text-primary)',
      }}>
        <div style={{ fontSize: '16px', fontWeight: 600, marginBottom: '8px' }}>
          Scan in progress
        </div>
        <div style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>
          Current status: <span className="mono" style={{ color: 'var(--action-blue)' }}>{result.status}</span>
        </div>
      </div>
    )
  }

  // Defensive Helpers to extract values from both Cached and Raw DB models
  const getSignals = (data) => {
    if (data.signal_scores) {
      const scores = { ...data.signal_scores }
      if (scores.static_ml_score === undefined || scores.static_ml_score === null) {
        const static_ml = data.static_ml_result
        if (static_ml) {
          scores.static_ml_score = static_ml.class_name === "Goodware"
            ? (1.0 - static_ml.confidence) * 100.0
            : static_ml.confidence * 100.0
        } else {
          scores.static_ml_score = 0.0
        }
      }
      if (scores.dynamic_ml_score === undefined || scores.dynamic_ml_score === null) {
        scores.dynamic_ml_score = scores.ml_score !== undefined ? scores.ml_score : 0.0
      }
      return scores
    }
    
    const static_ml = data.static_ml_result
    let static_ml_score = 0.0
    if (static_ml) {
      static_ml_score = static_ml.class_name === "Goodware"
        ? (1.0 - static_ml.confidence) * 100.0
        : static_ml.confidence * 100.0
    }
    
    const ml_confidence = data.ml_confidence || 0
    const ml_family = data.ml_class || "Benign"
    const dynamic_ml_score = ml_family === "Benign" ? (1.0 - ml_confidence) * 100 : ml_confidence * 100
    
    const vt_data = data.vt_data || {}
    let vt_score = 50
    if (vt_data.found) {
      const mal = vt_data.malicious_count || 0
      const harmless = vt_data.harmless_count || 0
      const undetected = vt_data.undetected_count || 0
      const suspicious = vt_data.suspicious_count || 0
      const total = mal + harmless + undetected + suspicious
      vt_score = total > 0 ? (mal / total) * 100 : 50
    }
    
    const sandbox_data = data.sandbox_data || {}
    const severity_score = sandbox_data.severity_score || 0
    const sandbox_score = Math.min(severity_score * 10.0, 100.0)
    
    const signature_verdict = data.signature_verdict
    const signature_score = signature_verdict === "TRUSTED" ? 0.0 : (signature_verdict === "SUSPICIOUS" ? 80.0 : 40.0)
    
    return { static_ml_score, dynamic_ml_score, vt_score, sandbox_score, signature_score }
  }

  const getThreatSummary = (data) => {
    if (data.threat_summary) return data.threat_summary
    const ml_family = data.ml_class || "Benign"
    const verdict = data.verdict || "CLEAN"
    const score = data.risk_score || 0
    const confidence = data.confidence_level || (data.ml_confidence >= 0.7 ? "HIGH" : data.ml_confidence >= 0.4 ? "MEDIUM" : "LOW")
    
    let summary = verdict === "MALICIOUS" || verdict === "SUSPICIOUS"
      ? `${ml_family} detected with ${confidence} confidence (Risk Score: ${score}/100)`
      : `Clean application (Risk Score: ${score}/100)`
      
    const details = []
    if (data.vt_detection_ratio && data.vt_detection_ratio !== "0/0") {
      details.push(`${data.vt_detection_ratio} AV engines flagged`)
    }
    if (data.signature_verdict) {
      details.push(`${data.signature_verdict.toLowerCase()} certificate signature`)
    }
    if (details.length > 0) {
      summary = `${summary} — ${details.join(', ')}`
    }
    return summary
  }

  const getIOCs = (data) => {
    if (data.iocs) return data.iocs
    const apk_hash = data.apk_hash
    const cert_hash = data.cert_hash || data.androguard_data?.certificate?.cert_hash
    const malware_family = data.ml_class
    const mitre_technique_ids = (data.sandbox_data?.mitre_attacks || []).map(m => m.id).filter(Boolean)
    return { apk_hash, cert_hash, malware_family, mitre_technique_ids }
  }

  const signals = getSignals(result)
  const summary = getThreatSummary(result)
  const mitre = result.mitre_attacks || result.sandbox_data?.mitre_attacks || []
  const topFeatures = result.ml_explanation?.top_features || []
  const dangerousPerms = result.dangerous_permissions || result.androguard_data?.dangerous_permissions || []
  const iocs = getIOCs(result)

  const getSignalColor = (score) => {
    if (score >= 70) return 'var(--danger)'
    if (score >= 40) return 'var(--warning)'
    return 'var(--success)'
  }

  return (
    <div>
      {/* Top Action Toolbar */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: '16px',
        flexWrap: 'wrap',
        gap: '12px',
      }}>
        <button
          className="btn-carbon-ghost"
          onClick={() => navigate('/')}
          style={{ padding: '4px 8px' }}
        >
          <ArrowLeft size={14} />
          Back to Dashboard
        </button>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          {result.apk_hash && (
            <button
              className="btn-carbon-secondary"
              onClick={() => copyToClipboard(result.apk_hash, 'apk_hash')}
              style={{ fontSize: '12px', padding: '6px 12px' }}
            >
              {copiedKey === 'apk_hash' ? (
                <>
                  <Check size={13} color="var(--success)" />
                  <span style={{ color: 'var(--success)' }}>Hash Copied</span>
                </>
              ) : (
                <>
                  <Copy size={13} />
                  <span>Copy SHA-256 Hash</span>
                </>
              )}
            </button>
          )}

          <button
            className="btn-carbon-secondary"
            onClick={exportReportJSON}
            style={{ fontSize: '12px', padding: '6px 12px' }}
          >
            <Download size={13} />
            Export Full JSON Report
          </button>
        </div>
      </div>

      {/* Top summary row */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '200px 1fr',
        gap: '1px',
        background: 'var(--border)',
        marginBottom: '16px',
      }}>
        {/* Risk score panel */}
        <div style={{
          background: 'var(--bg-secondary)',
          padding: '24px',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '12px',
        }}>
          <RiskScore score={result.risk_score} />
          <VerdictBadge verdict={result.verdict} />
        </div>

        {/* File metadata */}
        <div style={{
          background: 'var(--bg-secondary)',
          padding: '24px',
        }}>
          <div style={{
            fontSize: '12px',
            color: 'var(--text-secondary)',
            letterSpacing: '0.32px',
            textTransform: 'uppercase',
            fontWeight: 600,
            marginBottom: '16px',
          }}>
            File Information
          </div>
          <table style={{
            borderCollapse: 'collapse',
            width: '100%',
          }}>
            <tbody>
              {[
                ['File Name', result.file_name],
                ['Package', result.package_name || '—'],
                ['SHA-256', result.apk_hash ? (result.apk_hash.substring(0, 32) + '...') : '—'],
                ['Static ML', result.static_ml_result?.class_name || '—'],
                ['Static Confidence', result.static_ml_result?.confidence !== undefined && result.static_ml_result?.confidence !== null ? `${(result.static_ml_result.confidence * 100).toFixed(1)}%` : '—'],
                ['Dynamic ML', result.ml_class || '—'],
                ['Dynamic Confidence', result.ml_confidence !== undefined && result.ml_confidence !== null ? `${(result.ml_confidence * 100).toFixed(1)}%` : '—'],
                ['Signature', result.signature_verdict || '—'],
                ['VT Detection', result.vt_detection_ratio || '—'],
                ['Model Agreement', result.model_agreement || '—'],
              ].map(([label, value]) => {
                let cellColor = 'var(--text-primary)';
                if (label === 'Model Agreement') {
                  const val = String(value).toUpperCase();
                  if (val === 'BOTH_BENIGN') cellColor = 'var(--success)';
                  else if (val === 'BOTH_MALICIOUS') cellColor = 'var(--danger)';
                  else if (val === 'DISAGREEMENT') cellColor = 'var(--warning)';
                  else cellColor = 'var(--text-secondary)';
                }
                return (
                  <tr key={label}>
                    <td style={{
                      padding: '6px 0',
                      fontSize: '12px',
                      color: 'var(--text-secondary)',
                      width: '140px',
                      verticalAlign: 'top',
                    }}>
                      {label}
                    </td>
                    <td className="mono" style={{
                      padding: '6px 0',
                      fontSize: '13px',
                      color: cellColor,
                      wordBreak: 'break-all',
                    }}>
                      {value}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Threat summary */}
      {summary && (
        <div style={{
          background: 'var(--bg-elevated)',
          border: '1px solid var(--border)',
          borderLeft: '3px solid var(--warning)',
          padding: '12px 16px',
          marginBottom: '16px',
          fontSize: '13px',
          color: 'var(--text-primary)',
        }}>
          {summary}
        </div>
      )}

      {/* Signal scores */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(5, 1fr)',
        gap: '1px',
        background: 'var(--border)',
        marginBottom: '24px',
      }}>
        {[
          ['Static ML Score', signals.static_ml_score, Cpu],
          ['Dynamic ML Score', signals.dynamic_ml_score, Cpu],
          ['VT Score', signals.vt_score, Globe],
          ['Sandbox', signals.sandbox_score, AlertTriangle],
          ['Signature', signals.signature_score, Lock],
        ].map(([label, score, Icon]) => (
          <div
            key={label}
            style={{
              background: 'var(--bg-secondary)',
              padding: '16px',
              position: 'relative'
            }}
          >
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              marginBottom: '8px',
            }}>
              <span style={{
                fontSize: '12px',
                color: 'var(--text-secondary)',
                letterSpacing: '0.32px',
                textTransform: 'uppercase',
                fontWeight: 600,
              }}>
                {label}
              </span>
              <Icon
                size={16}
                color='var(--text-secondary)'
              />
            </div>
            <div className="mono" style={{
              fontSize: '24px',
              fontWeight: 600,
              color: getSignalColor(score),
            }}>
              {score !== undefined && score !== null ? score.toFixed(1) : '—'}
            </div>
            {/* Score bar */}
            <div style={{
              height: '2px',
              background: 'var(--bg-elevated)',
              marginTop: '8px',
            }}>
              <div style={{
                height: '100%',
                width: `${Math.min(score || 0, 100)}%`,
                background: getSignalColor(score),
              }} />
            </div>
          </div>
        ))}
      </div>

      {/* Model Agreement Banner */}
      {result.model_agreement && result.model_agreement !== 'UNKNOWN' && (
        <div style={{
          background: 'var(--bg-elevated)',
          border: '1px solid var(--border)',
          borderLeft: `3px solid ${
            result.model_agreement === 'BOTH_BENIGN'
              ? 'var(--success)'
              : result.model_agreement === 'BOTH_MALICIOUS'
                ? 'var(--danger)'
                : 'var(--warning)'
          }`,
          padding: '12px 16px',
          marginBottom: '16px',
          fontSize: '13px',
          color: 'var(--text-primary)',
        }}>
          {result.model_agreement === 'BOTH_BENIGN' && (
            `Both ML models agree: application is benign (Static: Goodware, Dynamic: ${result.ml_class || 'Benign'})`
          )}
          {result.model_agreement === 'BOTH_MALICIOUS' && (
            `Both ML models flag this as malicious (Static: Malware, Dynamic: ${result.ml_class || 'Benign'})`
          )}
          {result.model_agreement === 'DISAGREEMENT' && (
            `ML models disagree — manual review recommended (Static: ${
              result.static_ml_result?.class_name || 'Unknown'
            }, Dynamic: ${result.ml_class || 'Benign'}). VT and sandbox signals are the tiebreaker.`
          )}
        </div>
      )}

      {/* Three column: SHAP features + Static SHAP + MITRE */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '1fr 1fr 1fr',
        gap: '16px',
        marginBottom: '16px',
      }}>

        {/* Dynamic SHAP top features */}
        <div style={{
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border)',
        }}>
          <div style={{
            padding: '10px 16px',
            borderBottom: '1px solid var(--border)',
          }}>
            <div style={{
              fontSize: '12px',
              color: 'var(--text-secondary)',
              letterSpacing: '0.32px',
              textTransform: 'uppercase',
              fontWeight: 600,
            }}>
              Dynamic ML — SHAP Feature Explanation
            </div>
            <div style={{
              fontSize: '11px',
              color: 'var(--text-secondary)',
              marginTop: '2px',
            }}>
              Top syscall/binder features driving the dynamic classification
            </div>
          </div>
          <div style={{ padding: '0' }}>
            {topFeatures.length === 0 ? (
              <div style={{
                padding: '16px',
                color: 'var(--text-placeholder)',
                fontSize: '13px',
              }}>
                No SHAP data available
              </div>
            ) : topFeatures.map((f, i) => (
              <div
                key={i}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '8px 16px',
                  borderBottom: '1px solid var(--border-subtle)',
                }}
              >
                <span className="mono" style={{
                  fontSize: '12px',
                  color: 'var(--text-primary)',
                  flex: 1,
                  wordBreak: 'break-all',
                }}>
                  {f.feature}
                </span>
                <span style={{
                  fontSize: '11px',
                  color: f.direction === 'increases_risk'
                    ? 'var(--danger)'
                    : 'var(--success)',
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  letterSpacing: '0.16px',
                  marginLeft: '8px',
                }}>
                  {f.direction === 'increases_risk' ? '▲' : '▼'}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Static ML top features */}
        <div style={{
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border)',
        }}>
          <div style={{
            padding: '10px 16px',
            borderBottom: '1px solid var(--border)',
          }}>
            <div style={{
              fontSize: '12px',
              color: 'var(--text-secondary)',
              letterSpacing: '0.32px',
              textTransform: 'uppercase',
              fontWeight: 600,
            }}>
              Static ML — Permission Risk Factors
            </div>
            <div style={{
              fontSize: '11px',
              color: 'var(--text-secondary)',
              marginTop: '2px',
            }}>
              Top permissions/API calls driving the static classification
            </div>
          </div>
          <div style={{ padding: '0' }}>
            {(!result.static_ml_result?.top_features || result.static_ml_result.top_features.length === 0) ? (
              <div style={{
                padding: '16px',
                color: 'var(--text-placeholder)',
                fontSize: '13px',
              }}>
                No static SHAP data available
              </div>
            ) : result.static_ml_result.top_features.map((f, i) => (
              <div
                key={i}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '8px 16px',
                  borderBottom: '1px solid var(--border-subtle)',
                }}
              >
                <span className="mono" style={{
                  fontSize: '12px',
                  color: 'var(--text-primary)',
                  flex: 1,
                  wordBreak: 'break-all',
                }}>
                  {f.feature}
                </span>
                <span style={{
                  fontSize: '11px',
                  color: f.direction === 'increases_risk'
                    ? 'var(--danger)'
                    : 'var(--success)',
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  letterSpacing: '0.16px',
                  marginLeft: '8px',
                }}>
                  {f.direction === 'increases_risk' ? '▲' : '▼'}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* MITRE ATT&CK */}
        <div style={{
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border)',
        }}>
          <div style={{
            padding: '10px 16px',
            borderBottom: '1px solid var(--border)',
            fontSize: '12px',
            color: 'var(--text-secondary)',
            letterSpacing: '0.32px',
            textTransform: 'uppercase',
            fontWeight: 600,
          }}>
            MITRE ATT&CK Techniques
          </div>
          {mitre.length === 0 ? (
            <div style={{
              padding: '16px',
              color: 'var(--text-placeholder)',
              fontSize: '13px',
            }}>
              No sandbox MITRE data available
            </div>
          ) : (
            <table style={{
              width: '100%',
              borderCollapse: 'collapse',
            }}>
              <thead>
                <tr>
                  {['ID', 'Description', 'Severity'].map(h => (
                    <th key={h} style={{
                      padding: '8px 12px',
                      textAlign: 'left',
                      fontSize: '11px',
                      color: 'var(--text-secondary)',
                      letterSpacing: '0.32px',
                      textTransform: 'uppercase',
                      fontWeight: 600,
                      background: 'var(--bg-elevated)',
                      borderBottom: '1px solid var(--border)',
                    }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {mitre.map((m, i) => (
                  <tr key={i}>
                    <td className="mono" style={{
                      padding: '8px 12px',
                      fontSize: '12px',
                      color: 'var(--action-blue)',
                      borderBottom: '1px solid var(--border-subtle)',
                    }}>
                      {m.id}
                    </td>
                    <td style={{
                      padding: '8px 12px',
                      fontSize: '12px',
                      color: 'var(--text-primary)',
                      borderBottom: '1px solid var(--border-subtle)',
                    }}>
                      {m.description}
                    </td>
                    <td style={{
                      padding: '8px 12px',
                      borderBottom: '1px solid var(--border-subtle)',
                    }}>
                      <span style={{
                        fontSize: '10px',
                        fontWeight: 600,
                        textTransform: 'uppercase',
                        letterSpacing: '0.32px',
                        padding: '2px 6px',
                        background: m.severity?.includes('HIGH')
                          ? 'var(--danger)'
                          : m.severity?.includes('MEDIUM')
                            ? 'var(--warning)'
                            : 'var(--bg-elevated)',
                        color: m.severity?.includes('MEDIUM')
                          ? '#161616'
                          : 'var(--text-primary)',
                      }}>
                        {m.severity?.replace('IMPACT_SEVERITY_', '') || 'INFO'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Dangerous permissions */}
      {dangerousPerms.length > 0 && (
        <div style={{
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border)',
          marginBottom: '16px',
        }}>
          <div style={{
            padding: '10px 16px',
            borderBottom: '1px solid var(--border)',
            fontSize: '12px',
            color: 'var(--text-secondary)',
            letterSpacing: '0.32px',
            textTransform: 'uppercase',
            fontWeight: 600,
          }}>
            Dangerous Permissions ({dangerousPerms.length})
          </div>
          <div style={{
            padding: '12px 16px',
            display: 'flex',
            flexWrap: 'wrap',
            gap: '6px',
          }}>
            {dangerousPerms.map((perm, i) => (
              <span
                key={i}
                className="mono"
                style={{
                  background: 'rgba(218,30,40,0.1)',
                  border: '1px solid rgba(218,30,40,0.3)',
                  color: '#fa4d56',
                  padding: '3px 8px',
                  fontSize: '11px',
                  borderRadius: '0px',
                }}
              >
                {perm.replace('android.permission.', '')}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* IOCs */}
      <div style={{
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border)',
        paddingBottom: '8px'
      }}>
        <div style={{
          padding: '10px 16px',
          borderBottom: '1px solid var(--border)',
          fontSize: '12px',
          color: 'var(--text-secondary)',
          letterSpacing: '0.32px',
          textTransform: 'uppercase',
          fontWeight: 600,
          marginBottom: '8px'
        }}>
          Indicators of Compromise
        </div>
        <div style={{ padding: '8px 16px' }}>
          {[
            ['APK Hash', iocs.apk_hash],
            ['Certificate Hash', iocs.cert_hash],
            ['Malware Family', iocs.malware_family],
          ].map(([label, value]) => value && (
            <div
              key={label}
              style={{
                display: 'flex',
                gap: '16px',
                marginBottom: '10px',
              }}
            >
              <span style={{
                fontSize: '12px',
                color: 'var(--text-secondary)',
                width: '140px',
                flexShrink: 0,
              }}>
                {label}
              </span>
              <span className="mono" style={{
                fontSize: '12px',
                color: 'var(--text-primary)',
                wordBreak: 'break-all',
              }}>
                {value}
              </span>
            </div>
          ))}
          {iocs.mitre_technique_ids?.length > 0 && (
            <div style={{
              display: 'flex',
              gap: '16px',
              marginBottom: '10px',
            }}>
              <span style={{
                fontSize: '12px',
                color: 'var(--text-secondary)',
                width: '140px',
                flexShrink: 0,
              }}>
                MITRE Techniques
              </span>
              <div style={{
                display: 'flex',
                flexWrap: 'wrap',
                gap: '4px',
              }}>
                {iocs.mitre_technique_ids.map((id, i) => (
                  <span
                    key={i}
                    className="mono"
                    style={{
                      fontSize: '11px',
                      color: 'var(--action-blue)',
                      background: 'rgba(15,98,254,0.1)',
                      padding: '2px 6px',
                      border: '1px solid rgba(15,98,254,0.3)',
                    }}
                  >
                    {id}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Extracted Indicators of Compromise */}
      <div style={{
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border)',
        marginTop: '16px',
        paddingBottom: '16px'
      }}>
        <div style={{
          padding: '10px 16px',
          borderBottom: '1px solid var(--border)',
          fontSize: '12px',
          color: 'var(--text-secondary)',
          letterSpacing: '0.32px',
          textTransform: 'uppercase',
          fontWeight: 600,
        }}>
          Extracted Indicators of Compromise (Static Analysis)
        </div>

        <div style={{
          background: 'var(--bg-elevated)',
          borderBottom: '1px solid var(--border)',
          borderLeft: '3px solid var(--info)',
          padding: '12px 16px',
          fontSize: '12px',
          color: 'var(--text-secondary)',
          lineHeight: '1.4',
        }}>
          These indicators were extracted directly from the APK's decompiled strings via ASTRA's own static analysis — no external threat intelligence service was used. Results are unreviewed candidates and may include false positives from legitimate code (e.g. Java class/package identifiers).
        </div>

        {(!result.ioc_summary || result.ioc_summary.total_ioc_count === 0) ? (
          <div style={{
            padding: '16px',
            color: 'var(--text-placeholder)',
            fontSize: '13px',
            textAlign: 'center',
          }}>
            No indicators of compromise were extracted from this APK's static analysis.
          </div>
        ) : (
          <div>
            {/* Part B — Summary stat row */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(4, 1fr)',
              gap: '1px',
              background: 'var(--border)',
              borderBottom: '1px solid var(--border)',
            }}>
              {[
                ['URLs', result.ioc_summary.urls_found],
                ['IPs', result.ioc_summary.ips_found],
                ['Domains', result.ioc_summary.domains_found],
                ['Secrets/Endpoints', result.ioc_summary.secrets_found],
              ].map(([label, count]) => (
                <div
                  key={label}
                  style={{
                    background: 'var(--bg-secondary)',
                    padding: '16px',
                  }}
                >
                  <div style={{
                    fontSize: '12px',
                    color: 'var(--text-secondary)',
                    letterSpacing: '0.32px',
                    textTransform: 'uppercase',
                    fontWeight: 600,
                    marginBottom: '8px',
                  }}>
                    {label}
                  </div>
                  <div className="mono" style={{
                    fontSize: '24px',
                    fontWeight: 600,
                    color: 'var(--text-primary)',
                  }}>
                    {count}
                  </div>
                </div>
              ))}
            </div>

            {/* Part C — URLs and Secrets subsection */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: '1fr 1fr',
              gap: '16px',
              padding: '16px',
            }}>
              {/* Left Column: Extracted URLs */}
              <div style={{
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                display: 'flex',
                flexDirection: 'column',
              }}>
                <div style={{
                  padding: '10px 16px',
                  borderBottom: '1px solid var(--border)',
                  fontSize: '12px',
                  color: 'var(--text-secondary)',
                  letterSpacing: '0.32px',
                  textTransform: 'uppercase',
                  fontWeight: 600,
                }}>
                  Extracted URLs
                </div>
                <div style={{ maxHeight: '320px', overflowY: 'auto' }}>
                  {(!result.extracted_iocs?.network?.urls || result.extracted_iocs.network.urls.length === 0) ? (
                    <div style={{
                      padding: '16px',
                      color: 'var(--text-placeholder)',
                      fontSize: '13px',
                    }}>
                      No URLs extracted
                    </div>
                  ) : (
                    result.extracted_iocs.network.urls.map((url, i) => (
                      <div
                        key={i}
                        className="mono"
                        style={{
                          padding: '8px 16px',
                          borderBottom: '1px solid var(--border-subtle)',
                          fontSize: '12px',
                          color: 'var(--text-primary)',
                          wordBreak: 'break-all',
                        }}
                      >
                        {url}
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Right Column: Extracted Secrets & Endpoints */}
              <div style={{
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                display: 'flex',
                flexDirection: 'column',
              }}>
                <div style={{
                  padding: '10px 16px',
                  borderBottom: '1px solid var(--border)',
                  fontSize: '12px',
                  color: 'var(--text-secondary)',
                  letterSpacing: '0.32px',
                  textTransform: 'uppercase',
                  fontWeight: 600,
                }}>
                  Extracted Secrets & Endpoints
                </div>
                <div style={{ maxHeight: '320px', overflowY: 'auto' }}>
                  {(() => {
                    const secrets = result.extracted_iocs?.secrets || {};
                    const categories = [
                      { key: 'firebase_urls', label: 'Firebase URLs' },
                      { key: 'firebase_api_keys', label: 'Firebase API Keys' },
                      { key: 'telegram_bot_tokens', label: 'Telegram Bot Tokens' },
                      { key: 'discord_webhooks', label: 'Discord Webhooks' },
                      { key: 'aws_access_keys', label: 'AWS Access Keys' },
                      { key: 'generic_key_assignments', label: 'Generic Key Assignments' },
                    ];
                    const activeCategories = categories.filter(c => secrets[c.key]?.length > 0);
                    if (activeCategories.length === 0) {
                      return (
                        <div style={{
                          padding: '16px',
                          color: 'var(--text-placeholder)',
                          fontSize: '13px',
                        }}>
                          No secrets or endpoints detected
                        </div>
                      );
                    }
                    return activeCategories.map(cat => (
                      <div key={cat.key} style={{ marginBottom: '12px' }}>
                        <div style={{
                          padding: '6px 16px',
                          fontSize: '11px',
                          color: 'var(--text-secondary)',
                          letterSpacing: '0.32px',
                          textTransform: 'uppercase',
                          fontWeight: 600,
                          background: 'var(--bg-elevated)',
                        }}>
                          {cat.label}
                        </div>
                        {secrets[cat.key].map((item, idx) => (
                          <div
                            key={idx}
                            className="mono"
                            style={{
                              padding: '8px 16px',
                              borderBottom: '1px solid var(--border-subtle)',
                              fontSize: '12px',
                              color: 'var(--text-primary)',
                              wordBreak: 'break-all',
                            }}
                          >
                            {item}
                          </div>
                        ))}
                      </div>
                    ));
                  })()}
                </div>
              </div>
            </div>

            {/* Part D — IPs and Domains subsection */}
            <div style={{ padding: '0 16px 16px 16px' }}>
              <div style={{
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
              }}>
                <details style={{ width: '100%' }}>
                  <summary style={{
                    padding: '10px 16px',
                    fontSize: '12px',
                    color: 'var(--text-secondary)',
                    letterSpacing: '0.32px',
                    textTransform: 'uppercase',
                    fontWeight: 600,
                    cursor: 'pointer',
                    outline: 'none',
                  }}>
                    IPs and Domains ({(result.ioc_summary?.ips_found || 0) + (result.ioc_summary?.domains_found || 0)} candidates — click to expand)
                  </summary>
                  <div style={{
                    display: 'grid',
                    gridTemplateColumns: '1fr 1fr',
                    gap: '16px',
                    padding: '16px',
                    borderTop: '1px solid var(--border)',
                  }}>
                    {/* Left: IP Addresses */}
                    <div>
                      <div style={{
                        fontSize: '12px',
                        color: 'var(--text-secondary)',
                        textTransform: 'uppercase',
                        fontWeight: 600,
                        marginBottom: '8px',
                      }}>
                        IP Addresses
                      </div>
                      {(!result.extracted_iocs?.network?.ips || result.extracted_iocs.network.ips.length === 0) ? (
                        <div style={{
                          color: 'var(--text-placeholder)',
                          fontSize: '13px',
                        }}>
                          No IPs extracted
                        </div>
                      ) : (
                        <div style={{
                          display: 'flex',
                          flexWrap: 'wrap',
                          gap: '6px',
                        }}>
                          {result.extracted_iocs.network.ips.map((ip, i) => (
                            <span
                              key={i}
                              className="mono"
                              style={{
                                background: 'var(--bg-elevated)',
                                border: '1px solid var(--border)',
                                color: 'var(--text-primary)',
                                padding: '3px 8px',
                                fontSize: '11px',
                              }}
                            >
                              {ip}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Right: Domains */}
                    <div>
                      <div style={{
                        fontSize: '12px',
                        color: 'var(--text-secondary)',
                        textTransform: 'uppercase',
                        fontWeight: 600,
                        marginBottom: '8px',
                      }}>
                        Domains
                      </div>
                      {(!result.extracted_iocs?.network?.domains || result.extracted_iocs.network.domains.length === 0) ? (
                        <div style={{
                          color: 'var(--text-placeholder)',
                          fontSize: '13px',
                        }}>
                          No domains extracted
                        </div>
                      ) : (
                        <div style={{
                          display: 'flex',
                          flexWrap: 'wrap',
                          gap: '6px',
                          maxHeight: '300px',
                          overflowY: 'auto',
                        }}>
                          {result.extracted_iocs.network.domains.map((dom, i) => (
                            <span
                              key={i}
                              className="mono"
                              style={{
                                background: 'var(--bg-elevated)',
                                border: '1px solid var(--border)',
                                color: 'var(--text-primary)',
                                padding: '3px 8px',
                                fontSize: '11px',
                              }}
                            >
                              {dom}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </details>
              </div>
            </div>

            {/* Part E — Entropy-based suspected secrets */}
            <div style={{ padding: '0 16px' }}>
              <div style={{
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
              }}>
                <details style={{ width: '100%' }}>
                  <summary style={{
                    padding: '10px 16px',
                    fontSize: '12px',
                    color: 'var(--text-secondary)',
                    letterSpacing: '0.32px',
                    textTransform: 'uppercase',
                    fontWeight: 600,
                    cursor: 'pointer',
                    outline: 'none',
                  }}>
                    Suspected Secrets — Entropy Analysis (showing <strong style={{ color: 'var(--text-primary)' }}>{result.ioc_summary?.entropy_candidates_shown || 0}</strong><span style={{ color: 'var(--text-placeholder)', fontWeight: 400, fontSize: '11px' }}> of {result.ioc_summary?.entropy_candidates_found || 0} found</span> — click to expand)
                  </summary>
                  <div style={{
                    padding: '16px',
                    borderTop: '1px solid var(--border)',
                  }}>
                    <div style={{
                      fontStyle: 'italic',
                      fontSize: '11px',
                      color: 'var(--text-placeholder)',
                      marginBottom: '12px',
                    }}>
                      Includes DER certificate bytes and other binary artifacts that are not genuine secrets. Manual review required.
                    </div>
                    <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
                      {(!result.extracted_iocs?.entropy_candidates?.suspected_secrets || result.extracted_iocs.entropy_candidates.suspected_secrets.length === 0) ? (
                        <div style={{
                          color: 'var(--text-placeholder)',
                          fontSize: '13px',
                        }}>
                          No suspected secrets found
                        </div>
                      ) : (
                        result.extracted_iocs.entropy_candidates.suspected_secrets.map((item, i) => {
                          const val = item.value || '';
                          const totalLen = val.length;
                          let isPrintable = true;
                          if (totalLen > 0) {
                            const matchCount = (val.match(/[\x20-\x7E]/g) || []).length;
                            const printableRatio = matchCount / totalLen;
                            isPrintable = printableRatio >= 0.6;
                          }
                          
                          return (
                            <div
                              key={i}
                              style={{
                                padding: '8px 16px',
                                borderBottom: '1px solid var(--border-subtle)',
                              }}
                            >
                              {isPrintable ? (
                                <div
                                  className="mono"
                                  style={{
                                    fontSize: '11px',
                                    color: 'var(--text-primary)',
                                    wordBreak: 'break-all',
                                  }}
                                >
                                  {val.slice(0, 80) + (val.length > 80 ? '...' : '')}
                                </div>
                              ) : (
                                <div
                                  style={{
                                    fontSize: '11px',
                                    color: 'var(--text-placeholder)',
                                    fontStyle: 'italic',
                                  }}
                                >
                                  [Binary data — DER certificate bytes or non-printable content, not displayed]
                                </div>
                              )}
                              <div style={{
                                fontSize: '10px',
                                color: 'var(--text-secondary)',
                                marginTop: '4px',
                              }}>
                                entropy: {item.entropy} · length: {item.length} · type: {item.encoding_hint}
                              </div>
                            </div>
                          );
                        })
                      )}
                    </div>
                  </div>
                </details>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
