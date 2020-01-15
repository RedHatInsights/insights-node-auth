/*global module, require, process*/
'use strict';

const Mechanism        = require('./mechanism');
const request          = require('request');
const lodash           = require('lodash');
const systemIdPropsArr = ['header', 'url', 'method'];
const crypto           = require('crypto');
const parseString      = require('xml2js').parseString;
const checkedEnv       = require('./common/utils').checkEnv('SYSTEMIDAUTH', systemIdPropsArr);
const missingProps     = checkedEnv.missing;
const systemIdConfig   = checkedEnv.config;
const priv             = {};
const fs               = require('fs');
const path             = require('path');
const config           = require('../config');

class SystemIdAuth extends Mechanism {
    constructor (req, deferred) {
        super(req, deferred);
        this.systemIdConfig = systemIdConfig;

        if (missingProps.length > 0) {
            missingProps.forEach((prop) => {
                this.logger(`Missing prop: ${prop}`);
            }, this);
            throw new Error('SystemIdAuth configuration not setup!');
        }
    }

    buildUserObject (account_number) {
        return {
            is_active: true,
            is_entitled: true,
            is_org_admin: false,
            is_internal: false,
            sso_username: `systemid-system-${account_number}`,
            account_number: account_number
        };
    }

    getCacheKey (creds) {
        return crypto.createHash('sha512').update(creds.systemid).digest('base64');
    }

    ensureCredentials (creds) {
        if (!creds) {
            throw new Error('Error getting headers');
        }

        if (!creds.systemid) {
            throw new Error('No System ID');
        }
    }

    getCreds () {
        return {
            systemid: this.req.headers[this.systemIdConfig.header]
        };
    }

    getOpts (creds) {
        const opts = {
            method: 'GET',
            headers: {
                'x-rh-apitoken': this.config.phxproxyToken,
                'x-rh-systemid': creds.systemid,
                'x-rh-clientid': this.config.phxproxy_id,
                'x-rh-insights-env': this.config.insightsEnv
            },
            json: true,
            uri: this.config.middlewareHost + '/auth'
        };

       
        opts.cert = fs.readFileSync(path.resolve(__dirname, '../../../certs/backoffice-proxy.crt'));
        opts.ca = fs.readFileSync(path.resolve(__dirname, '../../../certs/backoffice-proxy.ca.crt'));

        return opts;
    }

    doRemoteCall (creds, callback) {
        const instance = this;

        request(instance.getOpts(creds), (err, res, body) => {
            if (err) {
                return instance.fail(`Got a request error ${instance.name}: ${err}`);
            }

            if (res.statusCode !== 200) {
                this.logger(body);
                return instance.fail(`Got a bad statusCode from backoffice-proxy: ${res.statusCode}`);
            }

            callback(body.user.account_number)
            return true;
        });
    }
}

module.exports = SystemIdAuth;
