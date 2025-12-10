# SlingShot Admin UI - Theme System

This directory contains the theme CSS files for the SlingShot Admin web interface. Themes can be dynamically switched using the theme selector dropdown in the header of both the dashboard and user management pages.

## Available Themes

1. **Default** - The original "hacker terminal" green-on-black theme
   - No separate CSS file (built into index.html and admin.html)
   - Neon green text on dark background
   - Monospace fonts

2. **Corporate Clean** (`corporate-clean/`)
   - Modern, minimal corporate aesthetic
   - Light mode with blue accent colors (#2563eb)
   - Inter font family
   - Clean typography and generous whitespace
   - Best for: Enterprise deployments, corporate environments

3. **Industrial Operations** (`industrial-ops/`)
   - Control room / operations center style
   - High contrast dark theme with amber/orange accents (#f59e0b)
   - JetBrains Mono font with scanline effects
   - Data-dense dashboard layout
   - Best for: 24/7 monitoring centers, security operations

4. **Material Design 3** (`material/`)
   - Google Material Design 3 inspired
   - Card-based layout with elevation shadows
   - Purple (#D0BCFF) and teal accent colors
   - Roboto font family
   - Best for: Modern web applications, familiar UX patterns

5. **Retro Synthwave** (`synthwave/`)
   - 80s neon aesthetic with cyberpunk vibes
   - Gradient backgrounds and glow effects
   - Pink (#ff2a6d), purple (#b967ff), and cyan (#05ffa1) neon colors
   - Orbitron font family
   - Best for: Making a statement, memorable branding

6. **Glassmorphism** (`glass/`)
   - Modern glass UI with frosted blur effects
   - Floating panels with subtle transparency
   - Soft gradients and light reflections
   - Animated gradient background with floating orbs
   - Poppins font family
   - Best for: Premium feel, cutting-edge aesthetic

## Theme Structure

Each theme directory contains:
- `dashboard.css` - Styles for the main dashboard (`index.html`)
- `admin.css` - Styles for the user management page (`admin.html`)

## How It Works

### Theme Selection
Both pages include a theme selector dropdown in the header that allows switching between themes in real-time.

### Theme Storage
The selected theme is stored in `localStorage` under the key `slingshot_theme`. This ensures:
- Theme preference persists across page reloads
- The same theme is applied to both dashboard and admin pages
- Theme choice is maintained per browser/device

### Theme Loading
When a theme is selected:
1. The theme CSS file is dynamically loaded via a `<link>` element
2. The theme preference is saved to localStorage
3. CSS custom properties in the theme file override the default styles
4. The same theme automatically applies when navigating between pages

### Default Theme
Selecting "Default Theme" removes the external theme stylesheet and reverts to the original built-in styles.

## Adding New Themes

To add a new theme:

1. Create a new directory in `themes/` (e.g., `themes/my-theme/`)
2. Create `dashboard.css` with styles for the dashboard
3. Create `admin.css` with styles for the admin page
4. Add the theme to both `<select>` dropdowns in `index.html` and `admin.html`:
   ```html
   <option value="my-theme">My Theme Name</option>
   ```

## Technical Details

### CSS Approach
Themes use CSS custom properties (CSS variables) to override colors, fonts, spacing, and other design tokens. The theme CSS files are loaded dynamically and take precedence over the default inline styles.

### Font Loading
Themes that use custom fonts (Inter, JetBrains Mono, Roboto, Orbitron, Poppins) load them from Google Fonts CDN. The font imports are included in each theme's CSS file.

### Browser Compatibility
- Modern browsers with CSS custom properties support
- Tested on Chrome, Firefox, Safari, Edge
- Fallback to default theme if CSS files fail to load

## Usage

No configuration is needed - the theme switcher is built into the UI. Simply select a theme from the dropdown menu in the header, and it will be applied immediately and persist across sessions.
