import { useState } from 'react'
import './Installation.css'

export default function Installation() {
  const [selectedPlatform, setSelectedPlatform] = useState('linux-haswell')
  const [copied, setCopied] = useState(false)

  const platforms = [
    { id: 'linux-haswell', name: 'Linux x86_64 (Haswell+)', file: 'floo-x86_64-linux-gnu-haswell.tar.gz', recommended: true },
    { id: 'linux-baseline', name: 'Linux x86_64', file: 'floo-x86_64-linux-gnu.tar.gz' },
    { id: 'linux-arm', name: 'Linux ARM64', file: 'floo-aarch64-linux-gnu.tar.gz' },
    { id: 'macos-m1', name: 'macOS Apple Silicon (M1+)', file: 'floo-aarch64-macos-m1.tar.gz', recommended: true },
    { id: 'macos-arm', name: 'macOS Apple Silicon', file: 'floo-aarch64-macos.tar.gz' },
    { id: 'macos-haswell', name: 'macOS Intel (Haswell+)', file: 'floo-x86_64-macos-haswell.tar.gz', recommended: true },
    { id: 'macos-intel', name: 'macOS Intel', file: 'floo-x86_64-macos.tar.gz' },
  ]

  const selectedFile = platforms.find(p => p.id === selectedPlatform)?.file

  const installCommand = `# Download and extract
curl -LO https://github.com/YUX/floo/releases/latest/download/${selectedFile}
tar xzf ${selectedFile}
cd ${selectedFile.replace('.tar.gz', '')}

# Make binaries executable
chmod +x flooc floos

# Test the binaries
./flooc --version
./floos --version`

  const copyToClipboard = () => {
    navigator.clipboard.writeText(installCommand)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <section id="installation" className="installation section">
      <div className="container">
        <h2 className="section-title">Installation</h2>

        <div className="installation-content">
          <div className="platform-selector">
            <h3 className="selector-title">Choose Your Platform</h3>
            <div className="platform-grid">
              {platforms.map(platform => (
                <button
                  key={platform.id}
                  className={`platform-btn ${selectedPlatform === platform.id ? 'active' : ''}`}
                  onClick={() => setSelectedPlatform(platform.id)}
                >
                  {platform.name}
                  {platform.recommended && (
                    <span className="recommended-badge">⚡ Recommended</span>
                  )}
                </button>
              ))}
            </div>
          </div>

          <div className="code-block-container">
            <div className="code-block-header">
              <span className="code-block-title">Installation Commands</span>
              <button onClick={copyToClipboard} className="copy-btn">
                {copied ? (
                  <>
                    <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
                      <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd"/>
                    </svg>
                    Copied!
                  </>
                ) : (
                  <>
                    <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
                      <path d="M8 3a1 1 0 011-1h2a1 1 0 110 2H9a1 1 0 01-1-1z"/>
                      <path d="M6 3a2 2 0 00-2 2v11a2 2 0 002 2h8a2 2 0 002-2V5a2 2 0 00-2-2 3 3 0 01-3 3H9a3 3 0 01-3-3z"/>
                    </svg>
                    Copy
                  </>
                )}
              </button>
            </div>
            <pre><code>{installCommand}</code></pre>
          </div>

          <div className="docs-links">
            <a href="https://github.com/YUX/floo#quick-start" target="_blank" rel="noopener noreferrer" className="doc-link">
              <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clipRule="evenodd"/>
              </svg>
              Configuration Guide
            </a>
            <a href="https://github.com/YUX/floo#quick-start" target="_blank" rel="noopener noreferrer" className="doc-link">
              <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M2 5a2 2 0 012-2h12a2 2 0 012 2v10a2 2 0 01-2 2H4a2 2 0 01-2-2V5zm3.293 1.293a1 1 0 011.414 0l3 3a1 1 0 010 1.414l-3 3a1 1 0 01-1.414-1.414L7.586 10 5.293 7.707a1 1 0 010-1.414zM11 12a1 1 0 100 2h3a1 1 0 100-2h-3z" clipRule="evenodd"/>
              </svg>
              CLI Reference
            </a>
            <a href="https://github.com/YUX/floo#troubleshooting" target="_blank" rel="noopener noreferrer" className="doc-link">
              <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-8-3a1 1 0 00-.867.5 1 1 0 11-1.731-1A3 3 0 0113 8a3.001 3.001 0 01-2 2.83V11a1 1 0 11-2 0v-1a1 1 0 011-1 1 1 0 100-2zm0 8a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd"/>
              </svg>
              Troubleshooting
            </a>
          </div>
        </div>
      </div>
    </section>
  )
}
