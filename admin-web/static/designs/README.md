# SlingShot Admin UI - Alternative Design Concepts

This directory contains 5 alternative layout and theme designs for the SlingShot Admin dashboard.

## Professional Designs

1. **Corporate Clean** (`design-1-corporate-clean.html`)
   - Modern, minimal corporate aesthetic
   - Light mode with blue accent colors
   - Clean typography and generous whitespace
   - Best for: Enterprise deployments, corporate environments

2. **Industrial Operations** (`design-2-industrial-ops.html`)
   - Control room / operations center style
   - High contrast dark theme with amber/orange accents
   - Data-dense dashboard layout
   - Best for: 24/7 monitoring centers, security operations

3. **Material Design 3** (`design-3-material.html`)
   - Google Material Design 3 inspired
   - Card-based layout with elevation shadows
   - Purple/teal accent colors
   - Best for: Modern web applications, familiar UX patterns

## Creative Designs

4. **Retro Synthwave** (`design-4-synthwave.html`)
   - 80s neon aesthetic with cyberpunk vibes
   - Gradient backgrounds and glow effects
   - Pink, purple, and cyan neon colors
   - Best for: Making a statement, memorable branding

5. **Glassmorphism Futuristic** (`design-5-glass.html`)
   - Modern glass UI with frosted blur effects
   - Floating panels with subtle transparency
   - Soft gradients and light reflections
   - Best for: Premium feel, cutting-edge aesthetic

## Layout Variations (Corporate Clean Theme)

Alternative arrangements of UI elements using the Corporate Clean theme:

### A. Video-Centric (`layout-a-video-centric.html`)
```
+--------+------------------------+
| HEADER                          |
+--------+------------------------+
| NODES  |        VIDEO           |
|        |------------------------|
|        |  STREAM | PTZ | REC    |
+--------+------------------------+
|            LOG / COMMAND        |
+---------------------------------+
```
- Large video takes center stage
- Nodes sidebar on left
- Horizontal control tabs below video
- Log spans full bottom width

### B. Split Horizontal (`layout-b-split-horizontal.html`)
```
+------------------------------------------+
|  LOGO  |  [cmd input]  |  STATUS  | LOG  |
+------------------------------------------+
| NODE1 | NODE2 | NODE3 | NODE4 | ...      |
+---------------------+--------------------+
|                     |     CONTROLS       |
|       VIDEO         |--------------------|
|                     |     ACTIVITY       |
+---------------------+--------------------+
```
- Nodes as horizontal scrollable cards at top
- Command bar integrated into header
- Video left, controls + log stacked right

### C. Minimal Sidebar (`layout-c-minimal-sidebar.html`)
```
+---+----------------------------------------+
| N |                                        |
| O |              VIDEO                     |
| D |                                        |
| E |----------------------------------------|
| S |  [floating control toolbar]            |
+---+----------------------------------------+
```
- Ultra-clean 56px icon sidebar
- Maximum video viewing space
- Slide-out panels for nodes and log
- Floating control toolbar
- Press '/' to open command input

## Admin User Management Themes

The same 5 theme designs have been adapted for the admin user management page (`admin.html`):

1. **Corporate Clean** (`admin-1-corporate-clean.html`)
   - Light mode with Inter font
   - Professional blue accents
   - Clean, modern user management interface

2. **Industrial Operations** (`admin-2-industrial-ops.html`)
   - Dark operations center aesthetic
   - JetBrains Mono font with scanline effects
   - Amber/orange accents for high contrast

3. **Material Design 3** (`admin-3-material.html`)
   - Roboto font with Material elevation shadows
   - Purple and teal color scheme
   - Card-based modal design

4. **Retro Synthwave** (`admin-4-synthwave.html`)
   - Orbitron font with neon glow effects
   - Animated gradient borders
   - Pink, cyan, and purple color palette

5. **Glassmorphism Futuristic** (`admin-5-glass.html`)
   - Poppins font with frosted glass panels
   - Animated gradient background with floating orbs
   - Soft purple-to-cyan gradients

## Usage

Each HTML file is a complete standalone implementation.

**For Dashboard Themes:**
1. Copy the desired `design-*.html` file content
2. Replace the content in `index.html`
3. Restart the admin-web server

**For Admin Page Themes:**
1. Copy the desired `admin-*.html` file content
2. Replace the content in `admin.html`
3. Restart the admin-web server

**For Layout Variations:**
1. Copy the desired `layout-*.html` file content
2. Replace the content in `index.html`
3. Restart the admin-web server

## Design Philosophy

All designs maintain the same functionality but transform the visual language and layout to suit different contexts and preferences.
