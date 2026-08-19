import './Footer.css'

export default function Footer() {
  return (
    <footer className="footer">
      <div className="container">
        <div className="footer-content">
          <div className="footer-brand">
            <div className="footer-logo">
              <span className="logo-text">Floo</span>
            </div>
            <p className="footer-tagline">
              High-throughput tunneling in Zig
            </p>
          </div>

          <div className="footer-links">
            <div className="footer-column">
              <h4 className="footer-title">Project</h4>
              <a href="https://github.com/YUX/floo" target="_blank" rel="noopener noreferrer">GitHub</a>
              <a href="https://github.com/YUX/floo/releases" target="_blank" rel="noopener noreferrer">Releases</a>
              <a href="https://github.com/YUX/floo/issues" target="_blank" rel="noopener noreferrer">Issues</a>
            </div>

            <div className="footer-column">
              <h4 className="footer-title">Documentation</h4>
              <a href="https://github.com/YUX/floo#readme" target="_blank" rel="noopener noreferrer">README</a>
              <a href="https://github.com/YUX/floo#quick-start" target="_blank" rel="noopener noreferrer">Configuration</a>
              <a href="https://github.com/YUX/floo#troubleshooting" target="_blank" rel="noopener noreferrer">Troubleshooting</a>
            </div>

            <div className="footer-column">
              <h4 className="footer-title">Community</h4>
              <a href="https://github.com/YUX/floo/discussions" target="_blank" rel="noopener noreferrer">Discussions</a>
              <a href="https://github.com/YUX/floo/blob/main/CONTRIBUTING.md" target="_blank" rel="noopener noreferrer">Contributing</a>
              <a href="https://github.com/YUX/floo/blob/main/LICENSE" target="_blank" rel="noopener noreferrer">License</a>
            </div>
          </div>
        </div>

        <div className="footer-bottom">
          <p>&copy; {new Date().getFullYear()} Floo. Licensed under Apache-2.0.</p>
          <p className="footer-built">Built with ❤️ in Zig</p>
        </div>
      </div>
    </footer>
  )
}
