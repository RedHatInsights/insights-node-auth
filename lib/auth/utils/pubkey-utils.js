/*global require, module, process*/
let sync_request = require('sync-request');
const debug  = require('debug')('auth');

module.exports.fetch = function fetch () {
    const tmp = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    const url = process.env.JWT_PUBKEY_URL || 'https://sso.redhat.com/auth/realms/redhat-external';
    try {
        if (url.indexOf('sso.redhat.com') === -1) {
            process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
        }

        const jsonResponse = JSON.parse(sync_request('GET', url, {
            headers: {
                'x-rh-apitoken': process.env.PHXPROXY_TOKEN,
                'x-rh-clientid': process.env.PHXPROXY_ID || 'insights-api',
                'x-rh-insights-env': process.env.INSIGHTS_ENV
            }
        }).getBody('utf-8'));
        const pubkey = jsonResponse.pubkey;

        debug(`Using this pubkey from ${url}:\n${pubkey}`);

        return pubkey;
    } catch (e) {
        console.error(e);
        console.error(`Failed to fetch pubkey from ${url} falling back to built in!`);
    } finally {
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = tmp;
    }

    // on error return false, the caller is responsible for falling back
    return false;
};
