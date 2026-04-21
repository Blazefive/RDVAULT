// vault-client.js
// Module réutilisable pour interagir avec Vault API

// SÉCURITÉ: Encode chaque segment d'un chemin d'engine
function encodeEnginePath(name) {
  return name.replace(/^\/+|\/+$/g, '')
    .split('/').map(s => encodeURIComponent(s)).join('/');
}

class VaultClient {
  constructor(vaultUrl, namespace = '') {
    this.vaultUrl = vaultUrl;
    this.namespace = namespace;
    this.token = null;
  }

  baseHeaders() {
    const headers = { 'X-Vault-Request': 'true' };
    if (this.token) headers['X-Vault-Token'] = this.token;
    if (this.namespace && this.namespace.trim()) {
      headers['X-Vault-Namespace'] = this.namespace.trim();
    }
    return headers;
  }

  async login(username, password) {
    try {
      const response = await fetch(`${this.vaultUrl}/v1/auth/ldap/login/${encodeURIComponent(username)}`, {
        method: 'POST',
        headers: this.baseHeaders(),
        body: JSON.stringify({ password })
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.errors?.[0] || 'Authentication failed');
      }

      const data = await response.json();
      this.token = data.auth?.client_token;

      // Récupérer le nom d'entité
      try {
        const tokenInfo = await this.lookupToken();
        const entityName = tokenInfo.entity_name || username;
        return { token: this.token, username: entityName };
      } catch {
        return { token: this.token, username };
      }
    } catch (err) {
      throw new Error('Login failed');
    }
  }

  async lookupToken() {
    const response = await fetch(`${this.vaultUrl}/v1/auth/token/lookup-self`, {
      method: 'GET',
      headers: this.baseHeaders()
    });

    if (!response.ok) throw new Error('Token lookup failed');

    const data = await response.json();
    return data.data;
  }

  async listEngines() {
    try {
      const response = await fetch(`${this.vaultUrl}/v1/sys/mounts`, {
        method: 'GET',
        headers: this.baseHeaders()
      });

      if (!response.ok) throw new Error('Failed to list engines');

      const data = await response.json();
      const engines = [];

      for (const [mountPath, cfg] of Object.entries(data)) {
        if (cfg && cfg.type === 'kv') {
          engines.push({
            name: mountPath.replace(/\/$/, ''),
            version: Number(cfg?.options?.version) === 2 ? 2 : 1
          });
        }
      }

      return engines;
    } catch (err) {
      console.error('Error listing engines');
      return [];
    }
  }

  async listSecretsV2(engineName) {
    try {
      const response = await fetch(
        `${this.vaultUrl}/v1/${encodeEnginePath(engineName)}/metadata?list=true`,
        { method: 'GET', headers: this.baseHeaders() }
      );

      if (response.status === 404) return [];
      if (!response.ok) throw new Error('Failed to list secrets');

      const data = await response.json();
      return (data.data?.keys || []).filter(k => !k.endsWith('/'));
    } catch (err) {
      console.error('Error listing secrets');
      return [];
    }
  }

  async listSecretsV1(engineName) {
    try {
      const response = await fetch(
        `${this.vaultUrl}/v1/${encodeEnginePath(engineName)}?list=true`,
        { method: 'GET', headers: this.baseHeaders() }
      );

      if (response.status === 404) return [];
      if (!response.ok) throw new Error('Failed to list secrets');

      const data = await response.json();
      return (data.data?.keys || []).filter(k => !k.endsWith('/'));
    } catch (err) {
      console.error('Error listing secrets');
      return [];
    }
  }

  async readSecretV2(engineName, key) {
    const response = await fetch(
      `${this.vaultUrl}/v1/${encodeEnginePath(engineName)}/data/${encodeURIComponent(key)}`,
      { method: 'GET', headers: this.baseHeaders() }
    );

    if (!response.ok) throw new Error('Failed to read secret');

    const data = await response.json();
    const secretData = data.data?.data || {};
    return {
      name: key,
      username: secretData.Username || '',
      password: secretData.Password || '',
      url: secretData.URL || '',
      website: secretData.Website || '',
      notes: secretData.Notes || ''
    };
  }

  async readSecretV1(engineName, key) {
    const response = await fetch(
      `${this.vaultUrl}/v1/${encodeEnginePath(engineName)}/${encodeURIComponent(key)}`,
      { method: 'GET', headers: this.baseHeaders() }
    );

    if (!response.ok) throw new Error('Failed to read secret');

    const data = await response.json();
    const secretData = data.data || {};
    return {
      name: key,
      username: secretData.Username || '',
      password: secretData.Password || '',
      url: secretData.URL || '',
      website: secretData.Website || '',
      notes: secretData.Notes || ''
    };
  }

  async getAllSecrets() {
    try {
      const engines = await this.listEngines();
      const allSecrets = [];

      for (const engine of engines) {
        try {
          const keys = engine.version === 2
            ? await this.listSecretsV2(engine.name)
            : await this.listSecretsV1(engine.name);

          for (const key of keys) {
            try {
              const secret = engine.version === 2
                ? await this.readSecretV2(engine.name, key)
                : await this.readSecretV1(engine.name, key);

              allSecrets.push({
                ...secret,
                engine: engine.name,
                version: engine.version
              });
            } catch (err) {
              console.error('Error reading secret');
            }
          }
        } catch (err) {
          console.error('Error processing engine');
        }
      }

      return allSecrets;
    } catch (err) {
      console.error('Error getting all secrets');
      return [];
    }
  }

  // Match les secrets par URL/Website
  async findSecretsByUrl(targetUrl) {
    try {
      const url = new URL(targetUrl);
      const hostname = url.hostname.toLowerCase();

      const allSecrets = await this.getAllSecrets();

      return allSecrets.filter(secret => {
        // Vérifier le champ Website
        if (secret.website) {
          try {
            const secretUrl = new URL(secret.website.startsWith('http')
              ? secret.website
              : `https://${secret.website}`);
            const secretHostname = secretUrl.hostname.toLowerCase();

            // Match exact ou sous-domaine
            if (secretHostname === hostname || hostname.endsWith(`.${secretHostname}`)) {
              return true;
            }
          } catch {
            // SÉCURITÉ: Ne pas utiliser .includes() — risque de faux positifs (ex: "evil-example.com".includes("example.com"))
          }
        }

        // Vérifier le champ URL (fallback)
        if (secret.url) {
          try {
            const secretUrl = new URL(secret.url.startsWith('http')
              ? secret.url
              : `https://${secret.url}`);
            const secretHostname = secretUrl.hostname.toLowerCase();

            if (secretHostname === hostname || hostname.endsWith(`.${secretHostname}`)) {
              return true;
            }
          } catch {
            // SÉCURITÉ: Ne pas utiliser .includes() — risque de faux positifs
          }
        }

        return false;
      });
    } catch (err) {
      console.error('Error finding secrets by URL');
      return [];
    }
  }
}

// Export pour utilisation dans background.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = VaultClient;
}
