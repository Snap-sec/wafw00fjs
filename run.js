#!/usr/bin/env node

const WAFDetector = require('./waf-detector');
const path = require('path');

/**
 * Main execution function
 */
async function main() {
    // Get target from command line arguments
    const args = process.argv.slice(2);
    
    if (args.length === 0) {
        console.log('Usage: node run.js <subdomain_or_ip> [options]');
        console.log('');
        console.log('Options:');
        console.log('  --find-all    Find all WAFs, do not stop on first match');
        console.log('  --no-attack   Do not make attack requests');
        console.log('  --timeout N   Set request timeout in milliseconds (default: 10000)');
        console.log('');
        console.log('Examples:');
        console.log('  node run.js example.com');
        console.log('  node run.js 192.168.1.1');
        console.log('  node run.js https://example.com --find-all');
        process.exit(1);
    }

    const target = args[0];
    const options = {
        findAll: args.includes('--find-all'),
        checkAttacks: !args.includes('--no-attack'),
        timeout: 10000
    };

    // Parse timeout if provided
    const timeoutIndex = args.indexOf('--timeout');
    if (timeoutIndex !== -1 && args[timeoutIndex + 1]) {
        options.timeout = parseInt(args[timeoutIndex + 1], 10) || 10000;
    }

    // Get path to waf_rules.json (same directory as this script)
    const rulesPath = path.join(__dirname, 'waf_rules.json');

    try {
        // Create detector instance
        const detector = new WAFDetector(rulesPath);
        
        // Detect WAFs
        const detectedWAFs = await detector.detectWAFs(target, options);

        // Print results
        console.log('');
        if (detectedWAFs.length > 0) {
            console.log('[+] WAF Detected!');
            detectedWAFs.forEach(waf => {
                console.log(`    ${waf}`);
            });
            console.log('');
            console.log(`[+] The site ${target} is behind ${detectedWAFs.join(' and/or ')} WAF.`);
        } else {
            console.log('[-] No WAF detected on', target);
        }
    } catch (error) {
        console.error('[!] Error:', error.message);
        process.exit(1);
    }
}

// Run if executed directly
if (require.main === module) {
    main().catch(error => {
        console.error('[!] Fatal error:', error);
        process.exit(1);
    });
}

module.exports = { main };

