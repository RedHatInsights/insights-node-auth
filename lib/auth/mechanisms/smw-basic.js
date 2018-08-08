/*global require, module*/
'use strict';

const fs = require('fs');
const path = require('path');
const Mechanism = require('./strata-basic'); // note this extends strata-basic not Mechanism
const request   = require('request');
const basicAuth = require('basic-auth');
const crypto    = require('crypto');

class SmwBasicAuth extends Mechanism {
    buildUserObject (json) {
        return {
            account_number: json.user.account_number,
            org_id: json.user.org_id,
            email: json.user.email,
            locale: json.user.locale,
            is_active: json.user.is_active,
            is_org_admin: json.user.is_org_admin,
            is_internal: json.user.is_internal,
            sso_username: json.user.username
        };
    }

    getCacheKey (creds) {
        return crypto.createHash('sha512').update(`${creds.login}:${creds.password}`).digest('base64');
    }

    ensureCredentials (creds) {
        if (!this.req.get('authorization')) {
            throw new Error('No Authorization header exists');
        }

        if (!creds) {
            throw new Error('Could not decode credentials from authorization header');
        }
    }

    getCreds () {
        const tmp = basicAuth.parse(this.req.get('authorization'));
        if (!tmp) {
            return false;
        }

        return {
            login: tmp.name,
            password: tmp.pass,
            hash: new Buffer(`${tmp.name}:${tmp.pass}`).toString('base64')
        };
    }

    doRemoteCall (creds, callback) {
        const instance = this;
        request(instance.getOpts(creds), (err, res, body) => {
            if (err) {
                return instance.fail(`Got a request error ${instance.name}: ${err}`);
            }

            if (res && res.statusCode !== 200) {
                return instance.fail(`Got a bad statusCode from backoffice-proxy: ${res.statusCode}`);
            }

            callback(body);
        });
    }

    getOpts (creds) {
        return {
            uri: `${this.config.middlewareHost}/auth`,
            method: 'GET',
            json: true,
            cert: fs.readFileSync(path.resolve(__dirname, '../../../certs/backoffice-proxy.crt')),
            ca: fs.readFileSync(path.resolve(__dirname, '../../../certs/backoffice-proxy.ca.crt')),
            headers: {
                authorization: `Basic ${creds.hash}`,
                'x-rh-apitoken': this.config.phxproxyToken,
                'x-rh-insights-env': this.config.insightsEnv
            }
        };
    }
};

module.exports = SmwBasicAuth;
