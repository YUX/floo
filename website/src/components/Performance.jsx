import { useEffect, useRef, useState } from 'react'
import './Performance.css'

export default function Performance() {
  const [isVisible, setIsVisible] = useState(false)
  const sectionRef = useRef(null)

  const benchmarks = [
    { name: 'Floo', throughput: 30.9, color: 'var(--accent-cyan)' },
    { name: 'Rathole', throughput: 16.6, color: 'var(--accent-purple)' },
    { name: 'FRP', throughput: 9.2, color: 'var(--accent-pink)' }
  ]

  const maxThroughput = Math.max(...benchmarks.map(b => b.throughput))

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsVisible(true)
        }
      },
      { threshold: 0.2 }
    )

    if (sectionRef.current) {
      observer.observe(sectionRef.current)
    }

    return () => observer.disconnect()
  }, [])

  return (
    <section ref={sectionRef} className="performance section">
      <div className="container">
        <h2 className="section-title">Performance</h2>

        <div className="performance-subtitle">
          Historical (v0.1.4 era): Apple M1 (4 vCPU) | Plaintext | Single Stream | iperf3. Not a current 0.3.0 claim.
        </div>

        <div className="benchmark-chart">
          {benchmarks.map((bench, index) => (
            <div key={index} className="benchmark-row">
              <div className="benchmark-label">
                <span className="benchmark-name">{bench.name}</span>
                <span className="benchmark-value">{bench.throughput} Gbps</span>
              </div>
              <div className="benchmark-bar-container">
                <div
                  className="benchmark-bar"
                  style={{
                    width: isVisible ? `${(bench.throughput / maxThroughput) * 100}%` : '0%',
                    background: bench.color,
                    boxShadow: `0 0 20px ${bench.color}`,
                    transitionDelay: `${index * 0.2}s`
                  }}
                >
                  {index === 0 && (
                    <div className="winner-badge">
                      <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
                        <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z"/>
                      </svg>
                      Champion
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="comparison-grid">
          <div className="comparison-card">
            <div className="comparison-icon">⚡</div>
            <div className="comparison-title">86% Faster</div>
            <div className="comparison-subtitle">Than Rathole</div>
          </div>
          <div className="comparison-card">
            <div className="comparison-icon">🚀</div>
            <div className="comparison-title">236% Faster</div>
            <div className="comparison-subtitle">Than FRP</div>
          </div>
          <div className="comparison-card">
            <div className="comparison-icon">💾</div>
            <div className="comparison-title">671 KB</div>
            <div className="comparison-subtitle">Combined Binary Size</div>
          </div>
        </div>
      </div>
    </section>
  )
}
