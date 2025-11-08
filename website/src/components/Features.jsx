import './Features.css'

export default function Features() {
  const features = [
    {
      icon: '⭐',
      title: 'Zero Dependencies',
      description: 'Built with only Zig stdlib. No external dependencies, supply chain, or security vulnerabilities.'
    },
    {
      icon: '🔐',
      title: 'Noise Protocol',
      description: 'Secure authentication with Noise XX + PSK. Choose from 5 AEAD ciphers including AEGIS-128L and AES-256-GCM.'
    },
    {
      icon: '🚀',
      title: 'Multiplexing',
      description: 'Expose multiple services through a single tunnel connection with intelligent routing.'
    },
    {
      icon: '⚡',
      title: 'Parallel Tunnels',
      description: 'Automatically matches your CPU cores and pins tunnel threads for maximum throughput.'
    },
    {
      icon: '📈',
      title: 'Live Metrics',
      description: 'Emit per-tunnel throughput and crypto timing with a single SIGUSR1—no extra agent required.'
    },
    {
      icon: '🌐',
      title: 'Proxy Support',
      description: 'Connect through SOCKS5 or HTTP CONNECT proxies for network flexibility.'
    },
    {
      icon: '💓',
      title: 'Auto-Reconnect',
      description: 'Heartbeat supervision with automatic reconnection. Never lose your tunnel.'
    },
    {
      icon: '📝',
      title: 'Config Management',
      description: 'Tweak TOML configs and restart floos/flooc to apply changes while we rework live reload.'
    },
    {
      icon: '📊',
      title: 'Built-in Diagnostics',
      description: 'Debug with --doctor and --ping commands. Troubleshooting made easy.'
    },
    {
      icon: '🎯',
      title: 'Token Auth',
      description: 'Per-service token authentication for fine-grained access control.'
    }
  ]

  return (
    <section className="features section">
      <div className="container">
        <h2 className="section-title">Features</h2>

        <div className="features-grid">
          {features.map((feature, index) => (
            <div key={index} className="feature-card" style={{ animationDelay: `${index * 0.1}s` }}>
              <div className="feature-icon">{feature.icon}</div>
              <h3 className="feature-title">{feature.title}</h3>
              <p className="feature-description">{feature.description}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
