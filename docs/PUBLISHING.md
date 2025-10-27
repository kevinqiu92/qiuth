# Publishing Qiuth to npm

This guide explains how to publish Qiuth to the npm registry.

## Prerequisites

1. **npm account**: Create one at https://www.npmjs.com/signup
2. **npm CLI logged in**: Run `npm login` and enter your credentials
3. **All tests passing**: Run `npm test` to verify
4. **Clean build**: Run `npm run build` to verify

## Pre-Publish Checklist

- [ ] All 318 tests passing (`npm test`)
- [ ] Build successful (`npm run build`)
- [ ] Version number updated in `package.json`
- [ ] CHANGELOG.md updated with release notes
- [ ] README.md is up to date
- [ ] API documentation is complete (`docs/api-reference.md`)
- [ ] No uncommitted changes (`git status`)
- [ ] Logged into npm (`npm whoami`)

## Publishing Steps

### 1. Verify Package Contents

Test what will be published:

```bash
npm pack --dry-run
```

This shows:
- Package size
- Files included
- Package metadata

Expected output:
```
npm notice 📦  qiuth@0.1.0
npm notice Tarball Contents
npm notice 1.1kB LICENSE
npm notice 10.3kB README.md
npm notice dist/ files...
npm notice package.json
npm notice total files: 15
```

### 2. Test Local Installation

Create a test package:

```bash
npm pack
```

This creates `qiuth-0.1.0.tgz`. Test it in another directory:

```bash
mkdir /tmp/test-qiuth
cd /tmp/test-qiuth
npm init -y
npm install /path/to/qiuth/qiuth-0.1.0.tgz

# Test the package
node -e "const qiuth = require('qiuth'); console.log(qiuth.VERSION);"
```

### 3. Run Pre-Publish Script

This runs automatically before publishing, but you can test it manually:

```bash
npm run prepublishOnly
```

This will:
1. Run type checking
2. Run all tests
3. Build the package

### 4. Publish to npm

For first-time publishing:

```bash
npm publish
```

For subsequent releases:

```bash
# Update version first
npm version patch  # or minor, or major
npm publish
```

### 5. Verify Publication

Check that the package is available:

```bash
npm view qiuth
```

Test installation:

```bash
npm install qiuth
```

### 6. Tag the Release

After successful publication:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## Version Management

Qiuth follows [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.0.0): Breaking changes
- **MINOR** (0.1.0): New features, backward compatible
- **PATCH** (0.0.1): Bug fixes, backward compatible

Update version:

```bash
# Patch release (0.1.0 -> 0.1.1)
npm version patch

# Minor release (0.1.0 -> 0.2.0)
npm version minor

# Major release (0.1.0 -> 1.0.0)
npm version major
```

This automatically:
1. Updates `package.json`
2. Creates a git commit
3. Creates a git tag

## Publishing Scoped Packages (Optional)

If you want to publish under a scope (e.g., `@yourname/qiuth`):

1. Update `package.json`:
```json
{
  "name": "@yourname/qiuth",
  ...
}
```

2. Publish with public access:
```bash
npm publish --access public
```

## Troubleshooting

### "You must be logged in to publish packages"

Run `npm login` and enter your credentials.

### "You do not have permission to publish"

The package name might be taken. Try:
- Different package name
- Scoped package (`@yourname/qiuth`)

### "Package name too similar to existing package"

npm prevents publishing packages with similar names to popular packages. Choose a more unique name.

### "prepublishOnly script failed"

Fix the errors shown in the output:
- Type errors: Run `npm run type-check`
- Test failures: Run `npm test`
- Build errors: Run `npm run build`

### "Package size too large"

Check what's being included:
```bash
npm pack --dry-run
```

Add files to `.npmignore` if needed.

## Post-Publication

### 1. Announce the Release

- Update GitHub README with npm badge
- Post on Twitter/social media
- Share in relevant communities
- Update project website

### 2. Monitor Issues

- Watch for bug reports
- Respond to questions
- Track download stats: https://npm-stat.com/charts.html?package=qiuth

### 3. Plan Next Release

- Review feature requests
- Prioritize bug fixes
- Update roadmap

## npm Package Badges

Add to README.md:

```markdown
[![npm version](https://badge.fury.io/js/qiuth.svg)](https://www.npmjs.com/package/qiuth)
[![npm downloads](https://img.shields.io/npm/dm/qiuth.svg)](https://www.npmjs.com/package/qiuth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
```

## Unpublishing (Emergency Only)

⚠️ **Warning**: Unpublishing is permanent and discouraged.

```bash
# Unpublish specific version (within 72 hours)
npm unpublish qiuth@0.1.0

# Unpublish entire package (within 72 hours)
npm unpublish qiuth --force
```

**Better alternatives:**
- Publish a patch version with fixes
- Deprecate the version: `npm deprecate qiuth@0.1.0 "Security vulnerability, use 0.1.1+"`

## Automation (Future)

Consider setting up automated publishing with GitHub Actions:

1. Create `.github/workflows/publish.yml` (already exists)
2. Add npm token to GitHub secrets
3. Publish automatically on git tags

## Support

- npm documentation: https://docs.npmjs.com/
- Semantic Versioning: https://semver.org/
- npm package best practices: https://docs.npmjs.com/packages-and-modules/contributing-packages-to-the-registry

---

## Quick Reference

```bash
# Check what will be published
npm pack --dry-run

# Test prepublish script
npm run prepublishOnly

# Publish
npm publish

# Verify
npm view qiuth

# Tag release
git tag v0.1.0
git push origin v0.1.0
```