import './Comparison.css'

export default function Comparison() {
  const comparisonData = [
    { feature: 'Language', floo: 'Zig', rathole: 'Rust', frp: 'Go' },
    { feature: 'Dependencies', floo: '0 ⭐', rathole: '27+ crates', frp: '34+ packages', highlight: 'floo' },
    { feature: 'Max Throughput (M1, historical v0.1.4)', floo: '29.4 Gbps', rathole: '18.1 Gbps', frp: '10.0 Gbps' },
    { feature: 'Binary Size', floo: '671 KB ⭐', rathole: '~2-4 MB', frp: '~24+ MB', highlight: 'floo' },
    { feature: 'Encryption', floo: 'Noise XX + PSK', rathole: 'Noise NK, TLS', frp: 'TLS' },
    { feature: 'Ciphers', floo: '9 AEAD + none', rathole: 'ChaCha20-Poly1305', frp: 'TLS standard', highlight: 'floo' },
    { feature: 'Parallel Tunnels', floo: '✅ Round-robin (1–64)', rathole: '🔶 Not documented', frp: '✅ Connection pool', highlight: 'floo' },
  { feature: 'Hot Config Reload', floo: '🔶 Restart (planned)', rathole: '✅ Dynamic services', frp: '✅ Admin API' },
    { feature: 'Built-in Diagnostics', floo: '✅ --doctor, --ping', rathole: '🔶 Logging only', frp: '✅ Dashboard, Prometheus' },
    { feature: 'Proxy Client', floo: '✅ SOCKS5, HTTP', rathole: '✅ SOCKS5, HTTP', frp: '✅ HTTP, SOCKS5' },
  ]

  return (
    <section className="comparison section">
      <div className="container">
        <h2 className="section-title">Feature Comparison</h2>
        <p className="comparison-subtitle">
          How Floo stacks up against similar tools
        </p>

        <div className="comparison-table-wrapper">
          <table className="comparison-table">
            <thead>
              <tr>
                <th>Feature</th>
                <th className="floo-column">Floo</th>
                <th>Rathole</th>
                <th>FRP</th>
              </tr>
            </thead>
            <tbody>
              {comparisonData.map((row, index) => (
                <tr key={index}>
                  <td className="feature-name">{row.feature}</td>
                  <td className={`value-cell ${row.highlight === 'floo' ? 'highlight' : ''}`}>
                    {row.floo}
                  </td>
                  <td className="value-cell">{row.rathole}</td>
                  <td className="value-cell">{row.frp}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="comparison-highlights">
          <div className="highlight-card">
            <div className="highlight-icon">🎯</div>
            <div className="highlight-title">Zero Dependencies</div>
            <div className="highlight-text">
              Only Zig stdlib - no supply chain vulnerabilities
            </div>
          </div>
          <div className="highlight-card">
            <div className="highlight-icon">⚡</div>
            <div className="highlight-title">Protocol v2</div>
            <div className="highlight-text">
              Explicit frame seq, u32 ServiceId, 9 AEAD ciphers + none
            </div>
          </div>
          <div className="highlight-card">
            <div className="highlight-icon">📦</div>
            <div className="highlight-title">Smallest Binaries</div>
            <div className="highlight-text">
              671 KB total vs 2-4 MB (Rathole) or 24+ MB (FRP)
            </div>
          </div>
        </div>

        <div className="comparison-note">
          <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd"/>
          </svg>
          All features verified against source repositories (Rathole v0.5.0, FRP v0.65.0).
          Benchmarks on identical hardware (Apple M1 MacBook Air) using iperf3.
        </div>
      </div>
    </section>
  )
}
