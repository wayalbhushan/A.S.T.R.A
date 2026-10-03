import React from 'react'
import { AlertTriangle, Info, ShieldCheck } from 'lucide-react'

const CORROBORATION_CONFIG = {
  exfil: {
    label: 'Exfiltration token embedded',
    danger: true,
  },
  lure: {
    label: 'Lure wording in app name or package',
    danger: false,
  },
  other_brand_cert: {
    label: "Signed by another bank's certificate",
    danger: true,
  },
  repackaged: {
    label: "Uses the brand's official package name",
    danger: false,
  },
}

export default function ImpersonationBanner({ impersonation }) {
  if (!impersonation || !impersonation.verdict || impersonation.verdict === 'NONE') {
    return null
  }

  const verdict = impersonation.verdict
  const brandName = impersonation.brand_name || 'bank'
  const evidence = impersonation.evidence || {}
  const corroboration = Array.isArray(evidence.corroboration) ? evidence.corroboration : []
  const isStrong = corroboration.includes('exfil') || corroboration.includes('other_brand_cert')
  const reasons = Array.isArray(impersonation.reasons) ? impersonation.reasons : []

  // Determine state configuration
  let stateKey = null
  let leftBorderColor = 'var(--info)'
  let Icon = Info
  let iconColor = 'var(--info)'
  let tagText = ''
  let tagBg = 'var(--bg-elevated)'
  let tagColor = 'var(--text-secondary)'
  let title = ''
  let sentence = ''

  if (verdict === 'IMPERSONATION') {
    if (isStrong) {
      stateKey = 'strong'
      leftBorderColor = 'var(--danger)'
      Icon = AlertTriangle
      iconColor = 'var(--danger)'
      tagText = 'IMPERSONATION'
      tagBg = 'var(--danger)'
      tagColor = '#ffffff'
      title = `Likely fake ${brandName} app`
      sentence = "This app uses a bank's name but is not signed by that bank's known certificates, and it carries additional warning signs."
    } else {
      stateKey = 'weak'
      leftBorderColor = 'var(--warning)'
      Icon = AlertTriangle
      iconColor = 'var(--warning)'
      tagText = 'POSSIBLE IMPERSONATION'
      tagBg = 'var(--warning)'
      tagColor = '#161616'
      title = `Possible fake ${brandName} app`
      sentence = "This app uses a bank's name and is signed by an unknown key. A legitimate app can also change its signing key, so verify before acting."
    }
  } else if (verdict === 'UNVERIFIED_CLAIM') {
    stateKey = 'unverified'
    leftBorderColor = 'var(--info)'
    Icon = Info
    iconColor = 'var(--info)'
    tagText = 'UNVERIFIED CLAIM'
    tagBg = 'var(--bg-elevated)'
    tagColor = 'var(--text-secondary)'
    title = `Claims to be ${brandName}`
    sentence = "This app uses a bank's name, but its signer is not in ASTRA's registry. Compare it with the official app before trusting it."
  } else if (verdict === 'GENUINE') {
    stateKey = 'genuine'
    leftBorderColor = 'var(--success)'
    Icon = ShieldCheck
    iconColor = 'var(--success)'
    tagText = 'GENUINE'
    tagBg = 'var(--success)'
    tagColor = '#ffffff'
    title = `Signed by a known ${brandName} certificate`
  } else {
    return null
  }

  // State d (GENUINE): Compact: header row only, no details, no reasons, no chips
  if (stateKey === 'genuine') {
    return (
      <div style={{
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border)',
        borderLeft: `4px solid ${leftBorderColor}`,
        padding: '16px',
        marginBottom: '16px',
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          flexWrap: 'wrap',
        }}>
          <Icon size={18} color={iconColor} style={{ flexShrink: 0 }} />
          <span style={{
            fontSize: '11px',
            fontWeight: 600,
            letterSpacing: '0.32px',
            padding: '2px 6px',
            background: tagBg,
            color: tagColor,
            textTransform: 'uppercase',
            userSelect: 'none',
          }}>
            {tagText}
          </span>
          <h3 style={{
            margin: 0,
            fontSize: '15px',
            fontWeight: 600,
            color: 'var(--text-primary)',
          }}>
            {title}
          </h3>
        </div>
      </div>
    )
  }

  // Key-value pairs for states a, b, c
  let certCountStr = ''
  if (typeof impersonation.registry_certs_for_brand === 'number') {
    certCountStr = impersonation.registry_certs_for_brand === 0
      ? 'None on file'
      : String(impersonation.registry_certs_for_brand)
  }

  const kvCandidates = [
    ['Claimed brand', impersonation.brand_name || ''],
    ['Matched on', evidence.matched_keyword ? `keyword "${evidence.matched_keyword}"` : ''],
    ['App name', evidence.label || ''],
    ['Package', evidence.package || ''],
    ['Signer (SHA-256)', evidence.cert_hash ? `${evidence.cert_hash.slice(0, 24)}...` : ''],
    ['Known certificates for this brand', certCountStr],
  ]

  const kvRows = kvCandidates.filter(([_, value]) => value !== '' && value !== null && value !== undefined)

  return (
    <div style={{
      background: 'var(--bg-secondary)',
      border: '1px solid var(--border)',
      borderLeft: `4px solid ${leftBorderColor}`,
      padding: '16px',
      marginBottom: '16px',
    }}>
      {/* Header row */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '10px',
        flexWrap: 'wrap',
        marginBottom: '10px',
      }}>
        <Icon size={18} color={iconColor} style={{ flexShrink: 0 }} />
        <span style={{
          fontSize: '11px',
          fontWeight: 600,
          letterSpacing: '0.32px',
          padding: '2px 6px',
          background: tagBg,
          color: tagColor,
          textTransform: 'uppercase',
          userSelect: 'none',
        }}>
          {tagText}
        </span>
        <h3 style={{
          margin: 0,
          fontSize: '15px',
          fontWeight: 600,
          color: 'var(--text-primary)',
        }}>
          {title}
        </h3>
      </div>

      {/* Explanatory sentence */}
      <div style={{
        fontSize: '13px',
        color: 'var(--text-primary)',
        lineHeight: '1.5',
        marginBottom: '14px',
      }}>
        {sentence}
      </div>

      {/* Key-Value Grid */}
      {kvRows.length > 0 && (
        <div style={{
          display: 'grid',
          gridTemplateColumns: '240px 1fr',
          gap: '6px 16px',
          marginBottom: '16px',
          padding: '12px',
          background: 'var(--bg-primary)',
          border: '1px solid var(--border-subtle)',
        }}>
          {kvRows.map(([label, value]) => (
            <React.Fragment key={label}>
              <div style={{
                fontSize: '12px',
                color: 'var(--text-secondary)',
                alignSelf: 'center',
              }}>
                {label}
              </div>
              <div className="mono" style={{
                fontSize: '13px',
                color: 'var(--text-primary)',
                wordBreak: 'break-all',
              }}>
                {value}
              </div>
            </React.Fragment>
          ))}
        </div>
      )}

      {/* Why ASTRA says this */}
      {reasons.length > 0 && (
        <div style={{ marginBottom: '14px' }}>
          <div style={{
            fontSize: '12px',
            fontWeight: 600,
            color: 'var(--text-secondary)',
            marginBottom: '6px',
            textTransform: 'uppercase',
            letterSpacing: '0.32px',
          }}>
            Why ASTRA says this
          </div>
          <ul style={{
            margin: 0,
            paddingLeft: '18px',
            color: 'var(--text-primary)',
            fontSize: '13px',
            lineHeight: '1.5',
          }}>
            {reasons.map((reason, idx) => (
              <li key={idx} style={{ marginBottom: '3px' }}>
                {reason}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Evidence Chips */}
      {corroboration.length > 0 && (
        <div style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: '8px',
          marginBottom: '12px',
        }}>
          {corroboration.map(key => {
            const config = CORROBORATION_CONFIG[key]
            const chipLabel = config ? config.label : key
            const isDanger = config ? config.danger : false
            return (
              <span
                key={key}
                style={{
                  fontSize: '11px',
                  padding: '3px 8px',
                  background: 'var(--bg-elevated)',
                  border: '1px solid var(--border)',
                  color: isDanger ? 'var(--danger)' : 'var(--text-primary)',
                  fontWeight: 500,
                  display: 'inline-flex',
                  alignItems: 'center',
                  userSelect: 'none',
                }}
              >
                {chipLabel}
              </span>
            )
          })}
        </div>
      )}

      {/* Minimum risk score note for state a and b */}
      {stateKey === 'strong' && (
        <div style={{
          fontSize: '12px',
          color: 'var(--text-secondary)',
          marginTop: '6px',
        }}>
          Minimum risk score for this finding: 75.
        </div>
      )}
      {stateKey === 'weak' && (
        <div style={{
          fontSize: '12px',
          color: 'var(--text-secondary)',
          marginTop: '6px',
        }}>
          Minimum risk score for this finding: 45.
        </div>
      )}
    </div>
  )
}
