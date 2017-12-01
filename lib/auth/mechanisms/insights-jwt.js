/*global require, module*/
'use strict';

const Mechanism = require('./mechanism');
const request   = require('request');
const lodash    = require('lodash');

// This class implements simple JWT-based token authentication.  The token contains the
// following fields:
//    usr  - sso_username of id used to create token
//    act  - account number that usr belongs to
//    urls - a map of {'<url_regex>': ['<operation>'], ...} this token permits, e.g.:
//           {'/r/insights/(v1/)?uploads/image$': ['POST']}

class InsightsJwtAuth extends Mechanism {
    constructor(req, deferred) {
        super(req, deferred);
        this.supportsCache = false;  // don't cache since tokens are url-specific
    }

    // Retrieve credentials from Authorization header of request
    getCreds() {
        const token = this.req.get('authorization');
        if (!token) {
            return false;
        }

        const hash = token.split('.')[2];

        if (!hash) {
            return false;
        }

        return {
            token: token,
            hash: hash
        };
    }


    // Perform basic credential validation (i.e. are they even present?)
    ensureCredentials(creds) {
        if (!creds) {
            throw new Error('No JWT in Authorization header');
        }
    }


    // We'd better not even try to cache these...
    getCacheKey() {
        return false;
    }


    // Validate the JWT and retrieve associated account info
    doRemoteCall(creds, callback) {
        const instance = this;

        // bail if creds are missing
        if (!creds) {
            return instance.fail(`Got a request error ${instance.name}: ${err}`);
        }

        // call insights internal endpoint to validate jwt
        request(instance.getOptsValidate(creds), (err, res, tokenBody) => {

            if (err) {
                return instance.fail(`Got a request error ${instance.name}: ${err}`);
            }

            if (res && res.statusCode !== 200) {
                return instance.fail(`Got a bad statusCode from ${instance.name}: ${res.statusCode}`);
            }

            if (!tokenBody) {
                return instance.fail(`Missing data in token authentication request from ${instance.name}`);
            }

            // is requested operation permitted by this token?
            if (!instance.urlPermitted(this.req, tokenBody.urls)) {
                return instance.fail(`Operation not permitted by token from ${instance.name}`);
            }

            // retrieve user account details
            request(instance.getOpts(tokenBody), (err, res, userBody) => {
                if (err) {
                    return instance.fail(`Got a request error ${instance.name}: ${err}`);
                }

                if (res && res.statusCode !== 200) {
                    return instance.fail(`Got a bad statusCode from ${instance.name}: ${res.statusCode}`);
                }

                userBody = userBody[0];
                if (!userBody) {
                    return instance.fail(`Got malformed user details response from ${instance.name}`);
                }

                // retrieve account role info
                return request(instance.getOptsRoles(userBody.login), (err, res, rolesBody) => {
                    userBody.roles = rolesBody;
                    callback(userBody);
                })
            });
        });
    }


    // Check url operation against list
    urlPermitted(req, list) {
        for (const pattern in list) {
            const re = new RegExp(pattern);
            const operations = list[pattern];

            if (re.test(req.url) && operations.indexOf(req.method) > -1) {
                return true;
            }
        }

        return false;
    }

    // Get details for JWT validation request
    getOptsValidate(creds) {
        return {
            uri: `${this.config.insightsInternalApiHost}/token/validate`,
            strictSSL: this.config.requestOptions.strictSSL,
            method: 'POST',
            body: creds,
            json: true,
            headers: {
                'content-type': 'application/json',
                'Authorization': this.config.insightsInternalApiKey
            }
        };
    }


    // Get details for user account info request
    getOpts(data) {
        return {
            uri: `${this.config.middlewareHost}/svcrest/user/v3/login=${data.usr}`,
            strictSSL: this.config.requestOptions.strictSSL,
            method: 'GET',
            json: true,
            headers: {
                'content-type': 'application/json',
            }
        };
    }


    // Get details for user account roles request
    getOptsRoles(login) {
        return {
            uri: `${this.config.middlewareHost}/svcrest/group/membership/login=${login}`,
            strictSSL: this.config.requestOptions.strictSSL,
            json: true,
            headers: {
                'useragent': 'access-insights-auth',
                'x-rhi-phxproxytoken': this.config.phxproxyToken
            }
        };
    }


    // Construct a record of authenticated user details.
    buildUserObject(json) {
        return {
            account_number: String(json.customer.oracleCustomerNumber),
            org_id: String(json.customer.id),
            email: json.personalInfo.email,
            locale: json.personalInfo.locale,
            is_active: json.active,
            is_org_admin: lodash.find(json.roles, { group: 'admin:org:all', roles: [ 'ADMIN' ] }) ? true : false,
            is_internal: lodash.find(json.roles, { group: 'redhat:employees', roles: [ 'USER' ] }) ? true : false,
            sso_username: json.login
        };
    }
};

module.exports = InsightsJwtAuth;
