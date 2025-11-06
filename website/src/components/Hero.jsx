import { useEffect, useState } from 'react'
import './Hero.css'

export default function Hero() {
  const [typedText, setTypedText] = useState('')
  const fullText = '29.4 Gbps'

  useEffect(() => {
    let index = 0
    const timer = setInterval(() => {
      if (index <= fullText.length) {
        setTypedText(fullText.slice(0, index))
        index++
      } else {
        clearInterval(timer)
      }
    }, 100)
    return () => clearInterval(timer)
  }, [])

  return (
    <div className="hero">
      <div className="hero-bg">
        <div className="flame flame-1"></div>
        <div className="flame flame-2"></div>
        <div className="flame flame-3"></div>
        <div className="portal-glow"></div>
      </div>

      <div className="container hero-content">
        <div className="hero-logo">
          <div className="floo-fireplace">
            <div className="fireplace-arch">╔═══════════╗</div>
            <div className="fireplace-fire">🔥 FLOO 🔥</div>
            <div className="fireplace-base">╚═══════════╝</div>
          </div>
        </div>

        <div className="hero-badge">
          <span className="pulse-dot"></span>
          The Floo Network • Powered by Zig
        </div>

        <h1 className="hero-title">
          High-Throughput
          <br />
          <span className="gradient-text">Tunneling</span>
        </h1>

        <p className="hero-subtitle">
          Zero dependencies. Maximum performance.
        </p>

        <div className="hero-metric">
          <div className="metric-value">
            {typedText}<span className="cursor">|</span>
          </div>
          <div className="metric-label">Encrypted Throughput</div>
        </div>

        <div className="hero-stats">
          <div className="stat">
            <div className="stat-value">62%</div>
            <div className="stat-label">Faster than Rathole</div>
          </div>
          <div className="stat">
            <div className="stat-value">194%</div>
            <div className="stat-label">Faster than FRP</div>
          </div>
          <div className="stat">
            <div className="stat-value">671 KB</div>
            <div className="stat-label">Total Binary Size</div>
          </div>
        </div>

        <div className="hero-actions">
          <a href="#installation" className="btn btn-primary">
            <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
              <path d="M10 2a1 1 0 011 1v8.586l2.293-2.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L9 11.586V3a1 1 0 011-1z"/>
              <path d="M4 14a1 1 0 011 1v2h10v-2a1 1 0 112 0v2a2 2 0 01-2 2H5a2 2 0 01-2-2v-2a1 1 0 011-1z"/>
            </svg>
            Get Started
          </a>
          <a href="https://github.com/YUX/floo" target="_blank" rel="noopener noreferrer" className="btn btn-secondary">
            <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M10 0C4.477 0 0 4.484 0 10.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0110 4.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.203 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.942.359.31.678.921.678 1.856 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0020 10.017C20 4.484 15.522 0 10 0z" clipRule="evenodd"/>
            </svg>
            View on GitHub
          </a>
        </div>
      </div>
    </div>
  )
}
