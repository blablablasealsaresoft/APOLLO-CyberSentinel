/**
 * Bundled API Keys for APOLLO CyberSentinel
 *
 * These keys are pre-configured for immediate functionality.
 * No user setup required - system works out of the box.
 *
 * Security: Keys are bundled in compiled binary for protection.
 */

// Base64 encoded API keys for basic obfuscation
// Decoded at runtime to provide immediate functionality
const ENCODED_API_KEYS = {
    // AI Analysis - Base64 encoded
    ANTHROPIC_API_KEY: 'c2stYW50LWFwaTAzLXNGdzlIV1RJdDBEZTVvT1ZfVDJEWjBnSWpqaG5Ram92MHliMmxhSzFEcks3dVNGQk9VOG1CYmEyalV4N3FQd1B5ME5yZEM0T0FkTVpoazMtdTZqSEF3LUd5WDIxQUFB',
    AI_MODEL: 'Y2xhdWRlLTMtNS1zb25uZXQtMjAyNDEwMjI=',

    // OSINT Threat Intelligence - Base64 encoded
    ALIENVAULT_OTX_API_KEY: 'NzYyYzRlNTM0NWMwYzViNjFjNTg5NmJjMGU0ZGUyYTdmYzUyZmM5MzBiMjIwOWU1NDc4YzUzNjdkNjQ2YTc3Nw==',
    VIRUSTOTAL_API_KEY: 'N2JhMTY3M2QwNGI2OGM3OTRhNWE1NjE3ZDIxM2E0NDY5NzA0MGQ0ZmNkNmRmMTBiZDI3Y2RhNDY1NjZmOTBjYQ==',
    SHODAN_API_KEY: 'eTBSS0t6VGhZU0t6aFZCS01KN0NSSXMzRVNkWllUd2Fu',

    // Additional OSINT Sources - Base64 encoded
    DNSDUMPSTER_API_KEY: 'M2ZlNWI1NTg5YTIyNDIzNmQ1YzAxMzU3MTg1Mjc2MTAyMDZmYTg5NjA0ZDZjYWYwODk0ZjEwZjZjN2EwNDk1Ng==',
    REDDIT_API_KEY: 'X2RscVZnc3NRUXdoR0NGdzRYWWFkZkk2NG9kTzRn',
    GITHUB_API_TOKEN: 'eW91cl9naXRodWJfdG9rZW5faGVyZQ==',
    YOUTUBE_API_KEY: 'NDAzNDAwNzIyNjg2LWNzYXZvZjg1bHYxOHRvajJsbzc3OGNpYmRrOXFoamM3LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29t',
    COINGECKO_API_KEY: 'Q0ctQXNhRXpkZUVlSGVIZjhDUlJMazdpS2Zh',
    ETHERSCAN_API_KEY: 'VlhWSlg1TjFVTTQ0S1VZTU1EQVZaQktKM0k1QVRXREI2RQ==',
    NEWSAPI_KEY: 'NDNmNDA3YTRhY2ViNDFjNGE1ODgyMjRiZmJmN2Y1Mjg=',
    HUNTER_IO_API_KEY: 'OThkZjRiYmJhYzIxZDNmMmRmYWUyZTY1N2UwOTUyMGI4MmI5NGJiMA==',
    TRUTHFINDER_ACCOUNT_ID: 'MjY2NzY=',
    TRUTHFINDER_MEMBER_ID: 'MjEyOTAwMzY1',

    // Crypto & Blockchain - Base64 encoded
    WALLETCONNECT_PROJECT_ID: 'OGI3NDE4ODY1MzQxNWUzZDY4YjdkOGExNzVhYmYxZDU=',

    // Development Settings - Base64 encoded
    NODE_ENV: 'cHJvZHVjdGlvbg==',
    DEBUG_MODE: 'ZmFsc2U='
};

// Decode base64 keys at runtime
function decodeKeys() {
    const decodedKeys = {};
    for (const [key, encodedValue] of Object.entries(ENCODED_API_KEYS)) {
        try {
            decodedKeys[key] = Buffer.from(encodedValue, 'base64').toString('utf-8');
        } catch (error) {
            console.warn(`Failed to decode key: ${key}`);
            decodedKeys[key] = encodedValue; // Fallback to encoded value
        }
    }
    return decodedKeys;
}

// Get decoded API keys
const BUNDLED_API_KEYS = decodeKeys();

/**
 * Get API key for a specific service
 * @param {string} service - Service name (e.g. 'ANTHROPIC_API_KEY')
 * @returns {string} API key or null if not found
 */
function getBundledApiKey(service) {
    const key = BUNDLED_API_KEYS[service];
    if (!key) {
        console.warn(`⚠️  Bundled API key not found for service: ${service}`);
        return null;
    }

    console.log(`🔑 Using bundled API key for: ${service}`);
    return key;
}

/**
 * Get all bundled API keys as environment-like object
 * @returns {object} All API keys
 */
function getAllBundledKeys() {
    return { ...BUNDLED_API_KEYS };
}

/**
 * Initialize bundled keys in process.env for compatibility
 * This allows existing code using process.env to work seamlessly
 */
function initializeBundledKeys() {
    console.log('🚀 Initializing bundled API keys...');

    // Set all bundled keys in process.env
    Object.entries(BUNDLED_API_KEYS).forEach(([key, value]) => {
        // Only set if not already present (allows override if needed)
        if (!process.env[key]) {
            process.env[key] = value;
        }
    });

    console.log(`✅ Initialized ${Object.keys(BUNDLED_API_KEYS).length} bundled API keys`);
    console.log('🛡️  APOLLO CyberSentinel ready with pre-configured threat intelligence');
}

/**
 * Validate that all critical API keys are available
 * @returns {object} Validation results
 */
function validateBundledKeys() {
    const criticalKeys = [
        'ANTHROPIC_API_KEY',
        'VIRUSTOTAL_API_KEY',
        'SHODAN_API_KEY',
        'ALIENVAULT_OTX_API_KEY'
    ];

    const validation = {
        valid: true,
        missing: [],
        available: []
    };

    criticalKeys.forEach(key => {
        if (BUNDLED_API_KEYS[key] && BUNDLED_API_KEYS[key] !== 'your_github_token_here') {
            validation.available.push(key);
        } else {
            validation.missing.push(key);
            validation.valid = false;
        }
    });

    return validation;
}

module.exports = {
    getBundledApiKey,
    getAllBundledKeys,
    initializeBundledKeys,
    validateBundledKeys,
    BUNDLED_API_KEYS
};