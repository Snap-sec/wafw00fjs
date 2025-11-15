const https = require('https');
const http = require('http');
const fs = require('fs');
const { URL } = require('url');

class WAFDetector {
    constructor(rulesPath = './waf_rules.json') {
        this.rules = this.loadRules(rulesPath);
        this.detectedWAFs = [];
    }

    loadRules(rulesPath) {
        try {
            const data = fs.readFileSync(rulesPath, 'utf8');
            return JSON.parse(data);
        } catch (error) {
            throw new Error(`Failed to load rules: ${error.message}`);
        }
    }

    /**
     * Make HTTP/HTTPS request
     */
    makeRequest(url, options = {}) {
        return new Promise((resolve, reject) => {
            const urlObj = new URL(url);
            const protocol = urlObj.protocol === 'https:' ? https : http;
            
            const requestOptions = {
                hostname: urlObj.hostname,
                port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
                path: urlObj.pathname + urlObj.search,
                method: options.method || 'GET',
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    ...options.headers
                },
                timeout: options.timeout || 10000,
                rejectUnauthorized: false // Allow self-signed certificates
            };

            const req = protocol.request(requestOptions, (res) => {
                let data = '';
                
                res.on('data', (chunk) => {
                    data += chunk;
                });
                
                res.on('end', () => {
                    resolve({
                        statusCode: res.statusCode,
                        statusMessage: res.statusMessage,
                        headers: res.headers,
                        body: data,
                        cookies: this.extractCookies(res.headers['set-cookie'] || [])
                    });
                });
            });

            req.on('error', (error) => {
                reject(error);
            });

            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });

            if (options.body) {
                req.write(options.body);
            }

            req.end();
        });
    }

    extractCookies(setCookieHeaders) {
        const cookies = {};
        if (Array.isArray(setCookieHeaders)) {
            setCookieHeaders.forEach(cookie => {
                const parts = cookie.split(';')[0].split('=');
                if (parts.length === 2) {
                    cookies[parts[0].trim()] = parts[1].trim();
                }
            });
        }
        return cookies;
    }

    /**
     * Normalize header name for case-insensitive matching
     */
    getHeader(headers, headerName) {
        const lowerName = headerName.toLowerCase();
        for (const [key, value] of Object.entries(headers)) {
            if (key.toLowerCase() === lowerName) {
                return value;
            }
        }
        return null;
    }

    /**
     * Match regex pattern (handles escaped patterns from JSON)
     */
    matchPattern(text, pattern) {
        if (!text) return false;
        try {
            // Convert escaped patterns back to regex
            // JSON escapes backslashes, so \\. becomes \. in regex
            const regex = new RegExp(pattern, 'i');
            return regex.test(text);
        } catch (error) {
            // If pattern is invalid, try as literal string
            return text.includes(pattern);
        }
    }

    /**
     * Check if header matches rule
     */
    checkHeaderRule(response, rule) {
        const headerValue = this.getHeader(response.headers, rule.name);
        if (!headerValue) {
            // Check if header name itself is a regex pattern
            if (rule.name.includes('[') || rule.name.includes('(')) {
                // Header name is a regex pattern, check all headers
                for (const [key, value] of Object.entries(response.headers)) {
                    if (this.matchPattern(key, rule.name) && this.matchPattern(value, rule.pattern)) {
                        return true;
                    }
                }
            }
            return false;
        }
        return this.matchPattern(headerValue, rule.pattern);
    }

    /**
     * Check if content matches rule
     */
    checkContentRule(response, rule) {
        return this.matchPattern(response.body, rule.pattern);
    }

    /**
     * Check if cookie matches rule
     */
    checkCookieRule(response, rule) {
        const cookieString = Object.entries(response.cookies)
            .map(([key, value]) => `${key}=${value}`)
            .join('; ');
        
        // Also check Set-Cookie headers directly
        const setCookieHeaders = response.headers['set-cookie'] || [];
        const allCookies = cookieString + '; ' + setCookieHeaders.join('; ');
        
        return this.matchPattern(allCookies, rule.pattern);
    }

    /**
     * Check if reason matches rule
     */
    checkReasonRule(response, rule) {
        return this.matchPattern(response.statusMessage || '', rule.pattern);
    }

    /**
     * Check if status code matches rule
     */
    checkStatusRule(response, rule) {
        return response.statusCode === rule.code;
    }

    /**
     * Check helper function rules
     * Helper functions can use either AND or OR logic:
     * - OR: if any rule matches, return true (common pattern)
     * - AND: all rules must match (used in some cases like f5bigipasm)
     * We'll use OR logic by default, but also check for AND patterns
     */
    checkHelperFunctionRules(response, helperFunction) {
        const rules = helperFunction.rules;
        
        // Check if any rule matches (OR logic - most common)
        let anyMatch = false;

        if (rules.headers && rules.headers.length > 0) {
            if (rules.headers.some(rule => this.checkHeaderRule(response, rule))) {
                anyMatch = true;
            }
        }

        if (rules.content && rules.content.length > 0) {
            if (rules.content.some(rule => this.checkContentRule(response, rule))) {
                anyMatch = true;
            }
        }

        if (rules.cookies && rules.cookies.length > 0) {
            if (rules.cookies.some(rule => this.checkCookieRule(response, rule))) {
                anyMatch = true;
            }
        }

        if (rules.reason && rules.reason.length > 0) {
            if (rules.reason.some(rule => this.checkReasonRule(response, rule))) {
                anyMatch = true;
            }
        }

        if (rules.status && rules.status.length > 0) {
            if (rules.status.some(rule => this.checkStatusRule(response, rule))) {
                anyMatch = true;
            }
        }

        // Also check AND logic for cases where multiple content rules exist
        // (indicates all must match pattern)
        if (rules.content && rules.content.length > 1) {
            const allContentMatch = rules.content.every(rule => this.checkContentRule(response, rule));
            if (allContentMatch) {
                return true;
            }
        }

        // Check AND logic for reason + status combinations (common pattern)
        if (rules.reason && rules.reason.length > 0 && rules.status && rules.status.length > 0) {
            const reasonMatch = rules.reason.some(rule => this.checkReasonRule(response, rule));
            const statusMatch = rules.status.some(rule => this.checkStatusRule(response, rule));
            if (reasonMatch && statusMatch) {
                return true;
            }
        }

        return anyMatch;
    }

    /**
     * Check if WAF is detected based on response
     */
    checkWAF(response, waf, useAttackResponse = false) {
        const rules = waf.rules;
        let matches = 0;
        let requiredMatches = 0;

        // Check headers
        if (rules.headers && rules.headers.length > 0) {
            for (const rule of rules.headers) {
                if (rule.attack_required && !useAttackResponse) {
                    continue; // Skip attack-required rules for normal requests
                }
                requiredMatches++;
                if (this.checkHeaderRule(response, rule)) {
                    matches++;
                }
            }
        }

        // Check content
        if (rules.content && rules.content.length > 0) {
            for (const rule of rules.content) {
                if (rule.attack_required && !useAttackResponse) {
                    continue;
                }
                requiredMatches++;
                if (this.checkContentRule(response, rule)) {
                    matches++;
                }
            }
        }

        // Check cookies
        if (rules.cookies && rules.cookies.length > 0) {
            for (const rule of rules.cookies) {
                if (rule.attack_required && !useAttackResponse) {
                    continue;
                }
                requiredMatches++;
                if (this.checkCookieRule(response, rule)) {
                    matches++;
                }
            }
        }

        // Check reason
        if (rules.reason && rules.reason.length > 0) {
            for (const rule of rules.reason) {
                if (rule.attack_required && !useAttackResponse) {
                    continue;
                }
                requiredMatches++;
                if (this.checkReasonRule(response, rule)) {
                    matches++;
                }
            }
        }

        // Check status
        if (rules.status && rules.status.length > 0) {
            for (const rule of rules.status) {
                if (rule.attack_required && !useAttackResponse) {
                    continue;
                }
                requiredMatches++;
                if (this.checkStatusRule(response, rule)) {
                    matches++;
                }
            }
        }

        // Check helper functions
        if (rules.helper_functions && rules.helper_functions.length > 0) {
            for (const helperFunc of rules.helper_functions) {
                if (this.checkHelperFunctionRules(response, helperFunc)) {
                    matches++;
                    requiredMatches++;
                }
            }
        }

        // WAF is detected if at least one rule matches
        return matches > 0;
    }

    /**
     * Detect WAFs from a response
     */
    async detectWAFs(target, options = {}) {
        this.detectedWAFs = [];
        
        // Normalize target URL
        let url = target;
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = `https://${url}`;
        }

        try {
            // Make normal request
            console.log(`[*] Making request to ${url}...`);
            const normalResponse = await this.makeRequest(url, {
                timeout: options.timeout || 10000
            });

            // Check all WAFs against normal response
            for (const waf of this.rules.wafs) {
                if (this.checkWAF(normalResponse, waf, false)) {
                    this.detectedWAFs.push(waf.name);
                    if (!options.findAll) {
                        break; // Stop at first match if findAll is false
                    }
                }
            }

            // If no WAF detected and we should check attack responses
            if (this.detectedWAFs.length === 0 && options.checkAttacks !== false) {
                console.log(`[*] No WAF detected in normal response, trying attack request...`);
                
                // Make attack request (XSS payload)
                const attackPayload = '<script>alert("XSS");</script>';
                const attackUrl = new URL(url);
                attackUrl.searchParams.append('test', attackPayload);
                
                try {
                    const attackResponse = await this.makeRequest(attackUrl.toString(), {
                        timeout: options.timeout || 10000
                    });

                    // Check WAFs that require attack responses
                    for (const waf of this.rules.wafs) {
                        if (this.detectedWAFs.includes(waf.name)) {
                            continue; // Already detected
                        }
                        if (this.checkWAF(attackResponse, waf, true)) {
                            this.detectedWAFs.push(waf.name);
                            if (!options.findAll) {
                                break;
                            }
                        }
                    }
                } catch (error) {
                    console.log(`[!] Attack request failed: ${error.message}`);
                }
            }

            return this.detectedWAFs;
        } catch (error) {
            throw new Error(`Request failed: ${error.message}`);
        }
    }
}

module.exports = WAFDetector;

