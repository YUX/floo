# Floo Website

Modern, cyberpunk-themed project website for Floo, built with React and Vite.

## Features

- Dark/cyberpunk themed design with neon accents
- Animated hero section with performance metrics
- Interactive performance benchmarks
- Live GitHub integration (stars, releases)
- Fully responsive design
- Fast and optimized with Vite

## Development

### Prerequisites

- Node.js 20.19+ or 22.12+ and npm

### Install Dependencies

```bash
npm install
```

### Run Development Server

```bash
npm run dev
```

The website will be available at `http://localhost:5173`

### Build for Production

```bash
npm run build
```

The built files will be in the `dist/` directory.

### Preview Production Build

```bash
npm run preview
```

## Deployment

The website is automatically deployed to GitHub Pages when changes are pushed to the `main` branch (in the `website/` directory).

The deployment is handled by `.github/workflows/deploy-website.yml`.

### Manual Deployment

If you need to deploy manually:

1. Build the site: `npm run build`
2. The built files in `dist/` can be deployed to any static hosting service

## Project Structure

```
website/
├── src/
│   ├── components/         # React components
│   │   ├── Hero.jsx        # Hero section with animated metrics
│   │   ├── Features.jsx    # Features grid
│   │   ├── Performance.jsx # Performance benchmarks
│   │   ├── Installation.jsx # Installation guide
│   │   ├── GitHub.jsx      # GitHub stats integration
│   │   └── Footer.jsx      # Footer
│   ├── App.jsx             # Main app component
│   ├── App.css             # Global app styles
│   ├── index.css           # Global CSS variables and theme
│   └── main.jsx            # Entry point
├── index.html              # HTML template
├── vite.config.js          # Vite configuration
└── package.json            # Dependencies and scripts
```

## Customization

### Colors

Edit the CSS variables in `src/index.css`:

```css
:root {
    --accent-cyan: #00f3ff;
    --accent-pink: #ff006e;
    --accent-purple: #8b5cf6;
    /* ... */
}
```

### Content

- **Performance metrics**: Edit in `src/components/Performance.jsx`
- **Features**: Edit the `features` array in `src/components/Features.jsx`
- **Platform downloads**: Edit the `platforms` array in `src/components/Installation.jsx`

## License

MIT License - Same as the main Floo project
