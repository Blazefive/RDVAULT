// ========================================
// GÉNÉRATION DE SBOM (CycloneDX 1.5)
// ========================================
// Produit une nomenclature logicielle (Software Bill of Materials) à partir de
// package-lock.json, pour la traçabilité de la chaîne d'approvisionnement.
//
//   node scripts/generate-sbom.js        → écrit sbom.json à la racine
//   node scripts/generate-sbom.js out.json
//
// Format CycloneDX, lisible par Dependency-Track, Grype, Trivy, etc.
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const lockPath = path.join(ROOT, 'package-lock.json');
const pkgPath = path.join(ROOT, 'package.json');
const outPath = path.resolve(ROOT, process.argv[2] || 'sbom.json');

if (!fs.existsSync(lockPath)) {
  console.error('package-lock.json introuvable — lancez `npm install` d\'abord.');
  process.exit(1);
}

const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));

const seen = new Set();
const components = [];

function addComponent(name, version) {
  if (!name || !version) return;
  const key = `${name}@${version}`;
  if (seen.has(key)) return;
  seen.add(key);
  const purl = `pkg:npm/${name.replace('@', '%40')}@${version}`;
  components.push({
    type: 'library',
    'bom-ref': purl,
    name,
    version,
    purl,
  });
}

// package-lock v2/v3 : objet "packages" indexé par chemin (node_modules/...)
if (lock.packages && typeof lock.packages === 'object') {
  for (const [p, info] of Object.entries(lock.packages)) {
    if (!p.startsWith('node_modules/')) continue; // ignorer la racine ("")
    const name = p.slice(p.lastIndexOf('node_modules/') + 'node_modules/'.length);
    addComponent(name, info.version);
  }
} else if (lock.dependencies && typeof lock.dependencies === 'object') {
  // Repli v1
  const walk = (deps) => {
    for (const [name, info] of Object.entries(deps)) {
      addComponent(name, info.version);
      if (info.dependencies) walk(info.dependencies);
    }
  };
  walk(lock.dependencies);
}

components.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));

const bom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  serialNumber: 'urn:uuid:' + crypto.randomUUID(),
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    tools: [{ vendor: 'RDVAULT', name: 'generate-sbom', version: '1.0.0' }],
    component: {
      type: 'application',
      'bom-ref': `pkg:npm/${pkg.name}@${pkg.version}`,
      name: pkg.name,
      version: pkg.version,
    },
  },
  components,
};

fs.writeFileSync(outPath, JSON.stringify(bom, null, 2) + '\n', 'utf8');
console.log(`SBOM écrit : ${outPath} (${components.length} composants)`);
