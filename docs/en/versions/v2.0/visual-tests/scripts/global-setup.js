const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

module.exports = async () => {
  if (process.env.DOCS_BASE_URL) {
    return;
  }

  const repoRoot = path.resolve(__dirname, '..', '..', '..');
  const siteDir = path.resolve(__dirname, '..', '.site');

  try {
    fs.rmSync(siteDir, { recursive: true, force: true });
  } catch (error) {
    // Ignore failures removing previous output.
  }

  try {
    execSync(
      `mkdocs build --config-file mkdocs.yml --site-dir "${siteDir}"`,
      {
        cwd: repoRoot,
        stdio: 'inherit',
      }
    );
  } catch (error) {
    throw new Error(
      `Failed to build documentation site for visual tests. Ensure MkDocs is installed and available on PATH.\n${error.message}`
    );
  }
};
