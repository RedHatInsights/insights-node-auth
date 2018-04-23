/*global require, process, describe, it, before, afterEach, beforeEach Buffer*/

require('assert');
require('should');
const request = require('request');
const q       = require('bluebird');
const auth    = require('../index');
const Mocks   = require('./mocks.js');
const cache   = require('../lib/auth/cache');
const USER    = process.env.TEST_USERNAME;
const PASS    = process.env.TEST_PASSWORD;
const funcs   = {};

funcs.validateUser = (user) => {
    user.should.have.property('account_number', '540155');
    user.should.have.property('org_id', '1979710');
    user.should.have.property('is_active', true);
    user.should.have.property('is_org_admin', true);
    user.should.have.property('is_internal', false);
    user.should.have.property('sso_username', USER);
    user.should.have.property('email', 'ihands+insightstest@redhat.com');
    user.should.have.property('locale', 'en_US');
    user.should.have.property('mechanism');
    user.should.have.property('cachehit');
};

// In some places here...
// why not arrow???
// https://github.com/mochajs/mocha/issues/2018
// also before().timeout() does not seem to work, lame it works for it's though

describe('Functional Tests:', () => {
    describe('execChain', () => {
        let mocks  = Mocks.getMocks();
        let rh_jwt;

        before(function (done) {
            this.timeout(10 * 1000);
            const opts = {
                url: 'https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token',
                form: {
                    grant_type: 'password',
                    client_id: 'customer-portal',
                    username: USER,
                    password: PASS
                }
            };
            request.post(opts, (err, res, body) => {
                if (err) { console.err(err); return; }
                rh_jwt = JSON.parse(body).access_token;
                done();
            });
        });

        afterEach(() => {
            mocks = Mocks.getMocks();
        });

        describe('multiple', function () {
            it('should fall through various modules until it hits one that works', () => {
                const deferred = q.defer();
                mocks.addCookie('rh_jwt', rh_jwt);
                mocks.req.headers = {};
                mocks.req.get = (str) => {
                    if (str === 'authorization') {
                        return false;
                    }

                    return undefined;
                };

                auth.execChain(mocks.app, [auth.smwBasic, auth.cert, auth.keycloakJwt, auth.systemid], deferred);
                mocks.next(); // start the app

                return deferred.promise.then((user) => {
                    funcs.validateUser(user);
                    user.should.have.property('mechanism', auth.keycloakJwt.name);
                    user.should.have.property('cachehit', false);
                });
            });
        });

        describe('systemid', function () {
            it('should return a valid user object when valid creds are passed in', () => {
                const deferred = q.defer();

                mocks.req.headers = {};
                mocks.req.headers[process.env.SYSTEMIDAUTH_HEADER] = process.env.TEST_SYSTEMID;

                auth.execChain(mocks.app, [auth.keycloakJwt,  auth.systemid], deferred);
                mocks.next(); // start the app

                return deferred.promise.then((user) => {
                    user.should.have.property('account_number', '540155');
                    user.should.have.property('is_active', true);
                    user.should.have.property('is_org_admin', false);
                    user.should.have.property('is_internal', false);
                    user.should.have.property('sso_username', 'systemid-system-540155');
                    user.should.have.property('mechanism', 'SystemIdAuth');
                    user.should.have.property('cachehit', false);
                });
            }).timeout(15 * 1000);
        });

        describe('cert', function () {
            it('should return a valid user object when valid creds are passed in', () => {
                const deferred = q.defer();

                mocks.req.headers = {};
                mocks.req.headers[process.env.CERTAUTH_PROXYPROOFHEADER] = process.env.CERTAUTH_PROXYPROOF;
                mocks.req.headers[process.env.CERTAUTH_COMMONNAMEHEADER] = process.env.TEST_COMMON_NAME;
                mocks.req.headers[process.env.CERTAUTH_ISSUERHEADER] = process.env.CERTAUTH_TRUSTEDISSUER;

                auth.execChain(mocks.app, [auth.keycloakJwt,  auth.cert], deferred);
                mocks.next(); // start the app

                return deferred.promise.then((user) => {
                    user.should.have.property('account_number', '540155');
                    user.should.have.property('org_id', '1979710');
                    user.should.have.property('is_active', true);
                    user.should.have.property('is_org_admin', true);
                    user.should.have.property('is_internal', false);
                    user.should.have.property('sso_username', 'cert-system-540155');
                    user.should.have.property('mechanism', 'CertAuth');
                    user.should.have.property('cachehit', false);
                });
            }).timeout(15 * 1000);
        });

        describe('strata-basic', () => {
            it('should fail when invalid creds are passed in', (done) => {
                const deferred = q.defer();

                mocks.req.get = (str) => {
                    if (str === 'authorization') {
                        return 'Basic aW52YWxpZAo=';
                    }

                    return undefined;
                };

                auth.execChain(mocks.app, [auth.keycloakJwt,  auth.strataBasic], deferred);
                mocks.next(); // start the app

                deferred.promise.then(() => {
                    done(new Error('got a non 401 when bad credentials were passed in!'));
                }).catch((status) => {
                    status.should.equal(401);
                    done();
                });
            }).timeout(15 * 1000);

            it('should return a valid user object when valid creds are passed in', () => {
                const deferred = q.defer();

                mocks.req.get = (str) => {
                    if (str === 'authorization') {
                        return 'Basic ' + new Buffer(`${USER}:${PASS}`).toString('base64');
                    }

                    return undefined;
                };

                auth.execChain(mocks.app, [auth.keycloakJwt,  auth.strataBasic], deferred);
                mocks.next(); // start the app

                return deferred.promise.then((user) => {
                    funcs.validateUser(user);
                    user.should.have.property('cachehit', false);
                });
            }).timeout(15 * 1000);
        });

        describe('smw-basic', () => {
            it('should fail when invalid creds are passed in', (done) => {
                const deferred = q.defer();

                mocks.req.get = (str) => {
                    if (str === 'authorization') {
                        return 'Basic aW52YWxpZAo=';
                    }

                    return undefined;
                };

                auth.execChain(mocks.app, [auth.smwBasic], deferred);
                mocks.next(); // start the app

                deferred.promise.then(() => {
                    done(new Error('got a non 401 when bad credentials were passed in!'));
                }).catch((status) => {
                    status.should.equal(401);
                    done();
                });
            });

            it('should return a valid user object when valid creds are passed in', () => {
                const deferred = q.defer();

                mocks.req.get = (str) => {
                    if (str === 'authorization') {
                        return 'Basic ' + new Buffer(`${USER}:${PASS}`).toString('base64');
                    }

                    return undefined;
                };

                cache.test.flushAll();

                auth.execChain(mocks.app, [auth.smwBasic], deferred);
                mocks.next(); // start the app

                return deferred.promise.then((user) => {
                    funcs.validateUser(user);
                    user.should.have.property('cachehit', false);
                });
            }).timeout(10 * 1000);

            it('should return a *cached* valid user object when valid creds are passed in', () => {
                const deferred    = q.defer();

                mocks.req.get = (str) => {
                    if (str === 'authorization') {
                        return 'Basic ' + new Buffer(`${USER}:${PASS}`).toString('base64');
                    }

                    return undefined;
                };

                auth.execChain(mocks.app, [auth.smwBasic], deferred);
                mocks.next(); // start the app

                return deferred.promise.then((user) => {
                    funcs.validateUser(user);
                    user.should.have.property('cachehit', true);
                });
            }).timeout(100);

            it('should skip cache when valid creds are passed in and the skip header is present', () => {
                const deferred    = q.defer();

                mocks.req.get = (str) => {
                    if (str === 'authorization') {
                        return 'Basic ' + new Buffer(`${USER}:${PASS}`).toString('base64');
                    }

                    if (str === 'x-rh-shouldauthcache') {
                        return 'false';
                    }

                    return undefined;
                };

                auth.execChain(mocks.app, [auth.smwBasic], deferred);
                mocks.next(); // start the app

                return deferred.promise.then((user) => {
                    funcs.validateUser(user);
                    user.should.have.property('cachehit', false);
                });
            }).timeout(10 * 1000);

        });

        describe('keycloakJwt', function () {
            beforeEach(() => {
                mocks.addCookie('rh_jwt', rh_jwt);
            });

            it('should return a valid user object when valid creds are passed in', () => {
                const deferred = q.defer();
                auth.execChain(mocks.app, [auth.keycloakJwt], deferred);
                mocks.next(); // start the app
                return deferred.promise.then((user) => {
                    mocks.addCookie('rh_jwt', rh_jwt);
                    user.should.have.property('cachehit', false);
                });
            });

            it('should never cache a JWT hit', () => {
                const deferred = q.defer();
                const innerDeferred = q.defer();

                auth.execChain(mocks.app, [auth.keycloakJwt], deferred);
                mocks.next(); // start the app

                deferred.promise.then(() => {
                    mocks = Mocks.getMocks();
                    mocks.addCookie('rh_jwt', rh_jwt);

                    auth.execChain(mocks.app, [auth.keycloakJwt], innerDeferred);
                    mocks.next(); // start the app

                    innerDeferred.promise.then((user) => {
                        funcs.validateUser(user);
                        user.should.have.property('cachehit', false);
                    });
                });
                return innerDeferred.promise;
            });
        });
    });
});
