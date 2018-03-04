/*global require, module, process*/
'use strict';

const Mechanism    = require('./mechanism');
const request      = require('request');
const certPropsArr = ['commonNameHeader', 'issuerHeader', 'proxyProofHeader', 'proxyProof', 'trustedIssuer', 'trustedHost', 'candlepinFindOwnerUrl'];
const priv         = {};
const checkedEnv   = require('./common/utils').checkEnv('CERTAUTH', certPropsArr);
const missingProps = checkedEnv.missing;
const certConfig   = checkedEnv.config;

class CertAuth extends Mechanism {
    constructor(req, deferred) {
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

    buildUserObject(json) {
        return {
            account_number: String(json.oracleCustomerNumber),
            org_id: json.displayName,
            is_active: true,
            is_org_admin: true,
            is_internal: false,
            sso_username: `cert-system-${json.oracleCustomerNumber}`
        };
    }

    getCacheKey(creds) {
        return creds.cn;
    }

    ensureCredentials(creds) {
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

    getCreds() {
        return {
            cn: priv.decodeCommonName(this.req.headers[this.certConfig.commonNameHeader]),
            issuer: priv.decodeIssuer(this.req.headers[this.certConfig.issuerHeader]),
            proxyProof: this.req.headers[this.certConfig.proxyProofHeader]
        };
    }

    doRemoteCall(creds, callback) {
        const instance = this;
        request({
            headers: {
                accept: 'application/json',
                'user-agent': this.useragent,
                'x-rhi-phxproxytoken': this.config.phxproxyToken
            },
            strictSSL: this.config.requestOptions.strictSSL,
            uri: this.config.middlewareHost + this.certConfig.candlepinFindOwnerUrl + creds.cn
        }, (err, res, body) => {
            if (err) {
                return instance.fail(`Got a CandlePin request error in ${instance.name}: ${err}\n\n${res}`);
            }

            if (res.statusCode !== 200) {
                return instance.fail(`Got a bad statusCode from CandlePin: ${res.statusCode} - ${res.body}`);
            }

            try {
                const json = JSON.parse(body);
                callback(json);
            } catch(e) {
                return instance.fail(`Unable to decode JSON from CandlePin: ${e}`);
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
