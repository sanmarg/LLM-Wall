# LLM Wall Website Documentation

This directory contains the static website for LLM Wall, hosted on GitHub Pages.

## Structure

```
docs/
├── index.html          # Main entry point
├── css/
│   ├── main.css       # Primary styles
│   └── animations.css # Animation definitions
├── js/
│   ├── main.js        # Main functionality
│   └── animations.js  # Advanced animations
├── assets/            # Images and resources
├── _config.yml        # Jekyll configuration
├── .nojekyll          # Disable Jekyll processing
├── ARCHITECTURE.md    # Architecture documentation
├── DEPLOYMENT_GUIDE.md # Deployment guide
└── README.md          # This file
```

## Technology

- HTML5 with semantic markup
- CSS3 with custom properties and animations
- Vanilla JavaScript (ES6+)
- GitHub Pages for hosting

## Local Testing

```bash
cd docs
python -m http.server 8000
# Open http://localhost:8000
```

## Deployment

Push changes to the repository — GitHub Pages automatically rebuilds from the `/docs` directory.
