import { useEffect, useState } from 'react'
import './GitHub.css'

export default function GitHub() {
  const [repoData, setRepoData] = useState(null)
  const [latestRelease, setLatestRelease] = useState(null)

  useEffect(() => {
    // Fetch repository data
    fetch('https://api.github.com/repos/YUX/floo')
      .then(res => res.json())
      .then(data => setRepoData(data))
      .catch(err => console.error('Failed to fetch repo data:', err))

    // Fetch latest release
    fetch('https://api.github.com/repos/YUX/floo/releases/latest')
      .then(res => res.json())
      .then(data => setLatestRelease(data))
      .catch(err => console.error('Failed to fetch release data:', err))
  }, [])

  return (
    <section className="github section">
      <div className="container">
        <h2 className="section-title">Open Source</h2>

        <div className="github-grid">
          {repoData && (
            <div className="github-card stats-card">
              <div className="card-icon">⭐</div>
              <h3 className="card-title">GitHub Stats</h3>
              <div className="stats-grid">
                <div className="stat-item">
                  <div className="stat-value">{repoData.stargazers_count?.toLocaleString() || 0}</div>
                  <div className="stat-label">Stars</div>
                </div>
                <div className="stat-item">
                  <div className="stat-value">{repoData.forks_count?.toLocaleString() || 0}</div>
                  <div className="stat-label">Forks</div>
                </div>
                <div className="stat-item">
                  <div className="stat-value">{repoData.open_issues_count?.toLocaleString() || 0}</div>
                  <div className="stat-label">Issues</div>
                </div>
              </div>
              <a href="https://github.com/YUX/floo" target="_blank" rel="noopener noreferrer" className="card-link">
                View Repository →
              </a>
            </div>
          )}

          {latestRelease && latestRelease.tag_name && (
            <div className="github-card release-card">
              <div className="card-icon">🚀</div>
              <h3 className="card-title">Latest Release</h3>
              <div className="release-info">
                <div className="release-version">{latestRelease.tag_name}</div>
                <div className="release-date">
                  {new Date(latestRelease.published_at).toLocaleDateString('en-US', {
                    year: 'numeric',
                    month: 'long',
                    day: 'numeric'
                  })}
                </div>
              </div>
              <a href={latestRelease.html_url} target="_blank" rel="noopener noreferrer" className="card-link">
                View Release →
              </a>
            </div>
          )}

          <div className="github-card contribute-card">
            <div className="card-icon">💡</div>
            <h3 className="card-title">Contribute</h3>
            <p className="card-text">
              Floo is open source and welcomes contributions. Report bugs, suggest features, or submit pull requests.
            </p>
            <a href="https://github.com/YUX/floo/issues" target="_blank" rel="noopener noreferrer" className="card-link">
              Open an Issue →
            </a>
          </div>
        </div>

        <div className="license-info">
          <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M10 2a1 1 0 011 1v1.323l3.954 1.582 1.599-.8a1 1 0 01.894 1.79l-1.233.616 1.738 5.42a1 1 0 01-.285 1.05A3.989 3.989 0 0115 15a3.989 3.989 0 01-2.667-1.019 1 1 0 01-.285-1.05l1.715-5.349L11 6.477V16h2a1 1 0 110 2H7a1 1 0 110-2h2V6.477L6.237 7.582l1.715 5.349a1 1 0 01-.285 1.05A3.989 3.989 0 015 15a3.989 3.989 0 01-2.667-1.019 1 1 0 01-.285-1.05l1.738-5.42-1.233-.617a1 1 0 01.894-1.788l1.599.799L9 4.323V3a1 1 0 011-1zm-5 8.274l-.818 2.552c.25.112.526.174.818.174.292 0 .569-.062.818-.174L5 10.274zm10 0l-.818 2.552c.25.112.526.174.818.174.292 0 .569-.062.818-.174L15 10.274z" clipRule="evenodd"/>
          </svg>
          Licensed under Apache-2.0
        </div>
      </div>
    </section>
  )
}
