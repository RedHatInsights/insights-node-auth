/*global require, module, process*/
'use strict';

const Mechanism    = require('./mechanism');
const request      = require('request');
const certPropsArr = ['commonNameHeader', 'issuerHeader', 'proxyProofHeader', 'proxyProof', 'trustedIssuer', 'trustedHost', 'candlepinFindOwnerUrl'];
const priv         = {};
const checkedEnv   = require('./common/utils').checkEnv('CERTAUTH', certPropsArr);
const missingProps = checkedEnv.missing;
const certConfig   = checkedEnv.config;
const fs           = require('fs');
const path         = require('path');
const config       = require('../config');

class CertAuth extends Mechanism {
    constructor (req, deferred) {
        super(req, deferred);
        this.missingProps = missingProps;
        this.certConfig = certConfig;

        // Make cert auth blow up if someone tries to use it with missing props!
        if (missingProps.length > 0) {
            missingProps.forEach((prop) => {
                this.logger(`Missing prop: ${prop}`);
            }, this);

            throw new Error(`CertAuth configuration not setup! Missing properties: ${missingProps.join(', ')}`);
        }
    }

    buildUserObject (json) {
        return {
            account_number: String(json.user.account_number),
            org_id: json.user.org_id,
            is_active: true,
            is_org_admin: true,
            is_internal: false,
            sso_username: `cert-system-${json.user.account_number}`
        };
    }

    getCacheKey (creds) {
        return creds.cn;
    }

    ensureCredentials (creds) {
        if (!creds) {
            throw new Error('Error getting headers');
        }

        //////////////
        // Host checks
        if (this.nullEmptyOrUndefined(creds.proxyProof)) {
            throw new Error('Missing Proxy proof header');
        }

        if (creds.proxyProof !== this.certConfig.proxyProof) {
            throw new Error(`Bad Proxy proof, disabling cert auth (${this.certConfig.proxyProof})`);
        }

        ///////////
        // CN check
        if (this.nullEmptyOrUndefined(creds.cn)) {
            throw new Error('Missing CommonName header');
        }

        ////////////////
        // Issuer checks
        if (this.nullEmptyOrUndefined(creds.issuer)) {
            throw new Error('Missing Issuer header');
        }

        if (creds.issuer !== this.certConfig.trustedIssuer) {
            throw new Error('Invalid issuer');
        }
    }

    getCreds () {
        return {
            cn: priv.decodeCommonName(this.req.headers[this.certConfig.commonNameHeader]),
            issuer: priv.decodeIssuer(this.req.headers[this.certConfig.issuerHeader]),
            proxyProof: this.req.headers[this.certConfig.proxyProofHeader]
        };
    }

    doRemoteCall (creds, callback) {
        const instance = this;
        const opts = {
            headers: {
                accept: 'application/json',
                'x-rh-apitoken': this.config.phxproxyToken,
                'x-rh-certauth-cn': creds.cn,
                'x-rh-certauth-issuer': creds.issuer,
                'x-rh-insights-certauth-secret': creds.proxyProof,
                'x-rh-insights-env': this.config.insightsEnv
            },
            uri: this.config.middlewareHost + '/auth'
        };

        if (config.insightsEnv === 'prod') {
            opts.cert = fs.readFileSync(path.resolve(__dirname, '../../../certs/backoffice-proxy.crt'));
            opts.ca = fs.readFileSync(path.resolve(__dirname, '../../../certs/backoffice-proxy.ca.crt'));
        }

        request(opts, (err, res, body) => {
            if (err) {
                return instance.fail(`Got a request error ${instance.name}: ${err}`);
            }

            if (res.statusCode !== 200) {
                return instance.fail(`Got a bad statusCode from backoffice-proxy: ${res.statusCode}`);
            }

            try {
                const json = JSON.parse(body);
                callback(json);
            } catch (e) {
                return instance.fail(`Unable to decode JSON from backoffice-proxy: ${e}`);
            }

            return true;
        });

    }
};

// Private functions

priv.decodeCommonName = (str) => {
    return unescape(str).replace('/CN=', '').trim();
};

priv.decodeIssuer = (str) => {
    return unescape(str).trim();
};

module.exports = CertAuth;
