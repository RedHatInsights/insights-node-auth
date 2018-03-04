/*global require, module*/
'use strict';

const Mechanism = require('./mechanism');
const CertAuth  = require('./cert');
const request   = require('request');
const lodash    = require('lodash');
const debug     = require('debug')('auth');

// This class implements simple JWT-based token authentication.  The token contains the
// following fields:
//    type - cert | user
//  [ cn   - CN from cert ]
//    usr  - sso_username of id used to create token
//    act  - account number that token belongs to
//    urls - a map of {'<url_regex>': ['<operation>'], ...} this token permits, e.g.:
//           {'/r/insights/(v1/)?uploads/image$': ['POST']}

class InsightsJwtAuth extends Mechanism {
    constructor(req, deferred) {
        super(req, deferred);
        this.certAuth = new CertAuth(req, deferred);
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

        debug(`${instance.name} - doRemoteCall()`);

        // bail if creds are missing
        if (!creds) {
            return instance.fail(`${instance.name} - Credentials missing`);
        }

        // call insights internal endpoint to validate jwt
        request(instance.getOptsValidateJWT(creds), (err, res, tokenBody) => {

            if (err) {
                return instance.fail(`${instance.name} - Got token validation request error: ${err}`);
            }

            if (res && res.statusCode !== 200) {
                return instance.fail(`${instance.name} - Got a bad token validation statusCode: ${res.statusCode} - ${res.body}`);
            }

            if (!tokenBody) {
                return instance.fail(`${instance.name} - Token seems to be empty`);
            }

            if (!tokenBody.type) {
                return instance.fail(`${instance.name} - Token missing TYPE field`);
            }

            debug(`${instance.name} - valid token:`, JSON.stringify(tokenBody));

            // is requested operation even permitted by this token?
            if (!instance.urlPermitted(this.req, tokenBody.urls)) {
                return instance.fail(`${instance.name} - Operation not permitted by token`);
            }

            // for 'user' tokens...
            if (tokenBody.type === 'user') {
                debug(`${instance.name} - this is a user token...`);

                // retrieve user account details
                request(instance.getOptsUserDetails(tokenBody), (err, res, userBody) => {
                    if (err) {
                        return instance.fail(`${instance.name} - Got user details request error: ${err}`);
                    }

                    if (res && res.statusCode !== 200) {
                        return instance.fail(`${instance.name} - Got a bad user details statusCode: ${res.statusCode}`);
                    }

                    userBody = userBody[0];
                    if (!userBody) {
                        return instance.fail(`${instance.name} - Got malformed user details response`);
                    }

                    // retrieve account role info
                    return request(instance.getOptsUserRoles(userBody.login), (err, res, rolesBody) => {
                        if (err) {
                            return instance.fail(`${instance.name} - Got a user roles request error: ${err}`);
                        }

                        if (res && res.statusCode !== 200) {
                            return instance.fail(`${instance.name} - Got a bad user roles statusCode: ${res.statusCode}`);
                        }

                        userBody.is_org_admin = lodash.find(rolesBody, { group: 'admin:org:all', roles: [ 'ADMIN' ] });
                        userBody.is_internal = lodash.find(rolesBody, { group: 'redhat:employees', roles: [ 'USER' ] });
                        userBody.type = tokenBody.type;

                        callback(userBody);
                    })
                });
            }

            // for 'cert' tokens...
            else if (tokenBody.type === 'cert') {
                debug(`${instance.name} - this is a cert token...`);

                // reuse cert auth logic from CertAuth class
                return this.certAuth.doRemoteCall({cn: tokenBody.cn}, (data) => {
                    debug(`certAuth.doRemoteCall() returned: ${JSON.stringify(data)}`);
                    data.type = tokenBody.type;
                    this.buildUserObject(data);

                    callback(data);
                });
            }

            // for any other tokens...
            else {
                debug(`${instance.name} - token type unknown...`);
                return instance.fail(`${instance.name} - Unsupported token type: ${tokenBody.type}`);
            }
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
    getOptsValidateJWT(creds) {
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
    getOptsUserDetails(data) {
        return {
            uri: `${this.config.middlewareHost}/svcrest/user/v3/login=${data.usr}`,
            strictSSL: this.config.requestOptions.strictSSL,
            method: 'GET',
            json: true,
            headers: {
                'content-type': 'application/json',
                'user-agent': this.useragent,
                'x-rhi-phxproxytoken': this.config.phxproxyToken
            }
        };
    }


    // Get details for user account roles request
    getOptsUserRoles(login) {
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
        if (json.type === 'user') {
            return {
                account_number: String(json.oracleCustomerNumber || json.customer.oracleCustomerNumber),
                org_id: json.displayName || String(json.customer.id),
                email: json.personalInfo.email,
                locale: json.personalInfo.locale,
                is_active: json.active,
                is_org_admin: json.is_org_admin,
                is_internal: json.is_internal,
                sso_username: json.login
            };
        }

        if (json.type === 'cert') {
            return this.certAuth.buildUserObject(json);
        }
    }
}

module.exports = InsightsJwtAuth;
