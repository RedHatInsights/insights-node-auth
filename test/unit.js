/*global require, process, describe, it, beforeEach*/

require('assert');
require('should');
const td      = require('testdouble');
const Mocks   = require('./mocks');
const samples = require('./samples');
const request = td.replace('request');
const auth    = require('../index');
const q       = require('bluebird');
const funcs   = {};

funcs.validateUser = (user) => {
    user.should.have.property('account_number', samples.pub.accountNumber);
    user.should.have.property('org_id', samples.pub.orgId);
    user.should.have.property('email', samples.pub.email);
    user.should.have.property('locale', 'en_US');
    user.should.have.property('is_org_admin');
    user.should.have.property('is_internal');
    user.should.have.property('sso_username', samples.pub.ssoUsername);
};

describe('Unit Tests:', () => {
    describe('multiple', () => {
        describe('SmwBasicAuth and StrataBasicAuth', () => {
            it('should both give the same cache key', () => {
                const mocks = Mocks.getMocks();
                mocks.req.get = (str) => {
                    if (str === 'authorization') {
                        return 'VGVzdFVzZXI6VGVzdFBhc3M='; // TestUser:TestPass
                    }
                    throw new Error(`TestError: unimplemented req.get("${str}")`);
                };

                const smw    = new auth.smwBasic(mocks.req);
                const strata = new auth.strataBasic(mocks.req);
                const smwOutput = smw.getCacheKey(smw.getCreds());
                const strataOutput = strata.getCacheKey(strata.getCreds());

                smwOutput.should.equal(strataOutput);
            });
        });
    });

    describe('execChain', () => {

        const getFromise = (user) => {
            const fromise = {
                then: (cb) => {
                    cb({
                        user: user
                    });
                    return fromise;
                },
                catch: (cb) => {
                    cb('false');
                }
            };

            return fromise;
        };

        const addFailing = (arr, num) => {
            for (let i = 0; i < num; i++) {
                const mechanism = td.constructor(['tryAuth']);
                td.when(mechanism.prototype.tryAuth()).thenReturn(getFromise(false));
                arr.push(mechanism);
            }
        };

        const singleMockUserFailTest = (code, user) => {
            const mocks     = Mocks.getMocks();
            const deferred  = q.defer();
            const mechanism = td.constructor(['tryAuth']);
            td.when(mechanism.prototype.tryAuth()).thenReturn(getFromise(user));
            auth.execChain(mocks.app, [mechanism], deferred);
            mocks.next(); // start the app
            return deferred.promise.then((user) => {
                throw new Error('We should not reach the promise then here! ' + user);
            }).catch((e) => {
                e.should.equal(code);
            });
        };

        it('should fail the unexpected', () => {
            return singleMockUserFailTest(403, 'This is a test');
        });

        it('should 401 failed logins', () => {
            return singleMockUserFailTest(401, false);
        });

        it('should 401 a null user', () => {
            return singleMockUserFailTest(401, null);
        });

        it('should 403 users that are not active', () => {
            return singleMockUserFailTest(403, { is_active: false, account_number: 12345 });
        });

        it('should 402 when an account_number is \'undefined\'', () => {
            return singleMockUserFailTest(402, { is_active: true, account_number: 'undefined' });
        });

        it('should 402 when an account_number is undefined', () => {
            return singleMockUserFailTest(402, { is_active: true, account_number: undefined });
        });

        it('should 402 when an account_number is \'false\'', () => {
            return singleMockUserFailTest(402, { is_active: true, account_number: 'false' });
        });

        it('should 402 when an account_number is false', () => {
            return singleMockUserFailTest(402, { is_active: true, account_number: false });
        });

        it('should 402 when an account_number is \'null\'', () => {
            return singleMockUserFailTest(402, { is_active: true, account_number: 'null' });
        });

        it('should 402 when an account_number is null', () => {
            return singleMockUserFailTest(402, { is_active: true, account_number: null });
        });

        it('should 402 when an account_number contains alpha', () => {
            return singleMockUserFailTest(402, { is_active: true, account_number: '123edf3' });
        });

        it('should fall through mechanisms until one wins', () => {
            const mocks            = Mocks.getMocks();
            const deferred         = q.defer();
            const beforeMechanisms = [];
            const afterMechanisms  = [];

            addFailing(beforeMechanisms, 10);
            addFailing(afterMechanisms, 10);

            const passMechanism = td.constructor(['tryAuth']);
            const passUser = {
                is_active: true,
                account_number: 12345
            };

            beforeMechanisms.push(passMechanism);
            td.when(passMechanism.prototype.tryAuth()).thenReturn(getFromise(passUser));
            passMechanism.prototype.__defineGetter__('name', function () { return 'FooBar'; });

            auth.execChain(mocks.app, beforeMechanisms.concat(afterMechanisms), deferred);
            mocks.next(); // start the app

            return deferred.promise.then((user) => {
                td.config({ ignoreWarnings: true });
                beforeMechanisms.forEach((mechanism) => { td.verify(new mechanism().tryAuth(), {times: 1}); });
                afterMechanisms.forEach((mechanism)  => { td.verify(new mechanism().tryAuth(), {times: 1}); });
                td.config({ ignoreWarnings: false });
                user.should.equal(passUser);
                user.mechanism.should.equal('FooBar');
            }).catch((e) => {
                throw new Error('We should not reach the promise catch here! ' + e);
            });
        });

        it('should fall through mechanisms and die if none win', () => {
            const mocks      = Mocks.getMocks();
            const deferred   = q.defer();
            const mechanisms = [];

            addFailing(mechanisms, 10);
            auth.execChain(mocks.app, mechanisms, deferred);
            mocks.next(); // start the app

            return deferred.promise.then(() => {
                throw new Error('We should not reach the promise then here!');
            }).catch((status) => {
                mechanisms.forEach((mechanism) => {
                    td.config({ ignoreWarnings: true });
                    td.verify(new mechanism().tryAuth(), {times: 1});
                    td.config({ ignoreWarnings: false });
                });
                status.should.equal(401);
            });
        });
    });

    describe('smwBasic', () => {
        let mechanism;

        beforeEach(() => {

            // get a new one each time an it is run
            mechanism = new auth.smwBasic();
        });

        describe('doRemoteCall', () => {
            it('should call fail() on a non 200 response', (done) => {
                td.when(request(td.matchers.anything())).thenCallback(false, { statusCode: 500 }, 'test');

                mechanism.fail = (msg) => {
                    msg.should.equal('Got a bad statusCode from backoffice-proxy: 500');
                    done();
                };

                mechanism.doRemoteCall('fdsafas');
            });

            it('should call fail() on a reques error', (done) => {
                td.when(request(td.matchers.anything())).thenCallback('TEST ERROR', { statusCode: 500 }, 'test');

                mechanism.fail = (msg) => {
                    msg.should.equal('Got a request error SmwBasicAuth: TEST ERROR');
                    done();
                };

                mechanism.doRemoteCall('fdsafas');
            });
        });

        describe('buildUserObject', () => {
            const getInput = (override) => {
                return Object.assign(samples.smwBasicUserObject, override);
            };

            it('should look like the standard user object', () => {
                const userObject = mechanism.buildUserObject(getInput());
                funcs.validateUser(userObject);
                userObject.should.have.property('is_active', true);
                userObject.should.have.property('is_org_admin', true);
                userObject.should.have.property('is_internal', true);
            });
        });
    });

    describe('cert', () => {
        let mechanism;

        beforeEach(() => {

            // get a new one each time an it is run
            mechanism = new auth.cert();
        });

        describe('buildUserObject', () => {
            const getInput = (override) => {
                return Object.assign(samples.certUserObject, override);
            };

            const validateCertUser = (userObject) => {
                const input = getInput();
                userObject.should.have.property('account_number', samples.pub.accountNumber);
                userObject.should.have.property('org_id', samples.pub.orgId);
                userObject.should.have.property('is_org_admin');
                userObject.should.have.property('is_internal');
                userObject.should.have.property('sso_username', `SYSTEM-${input.cn}`);
            };

            it('should look like the standard user object', () => {
                const userObject = mechanism.buildUserObject(getInput());
                validateCertUser(userObject);
            });

            it('should handle Strings or Numbers', () => {
                const input = getInput();

                input.oracleCustomerNumber = String(input.oracleCustomerNumber);
                let userObject = mechanism.buildUserObject(input);
                validateCertUser(userObject);


                input.oracleCustomerNumber = Number(input.oracleCustomerNumber);
                userObject = mechanism.buildUserObject(input);
                validateCertUser(userObject);
            });
        });
    });

    describe('strataBasic', () => {
        let mechanism;

        beforeEach(() => {

            // get a new one each time an it is run
            mechanism = new auth.strataBasic();
        });

        describe('doRemoteCall', () => {
            it('should call fail() on a non 200 response', (done) => {
                td.when(request(td.matchers.anything())).thenCallback(false, { statusCode: 500 }, 'test');

                mechanism.fail = (msg) => {
                    msg.should.equal('Got a bad statusCode from backoffice-proxy: 500');
                    done();
                };

                mechanism.doRemoteCall('fdsafas');
            });

            it('should call fail() on a reques error', (done) => {
                td.when(request(td.matchers.anything())).thenCallback('TEST ERROR', { statusCode: 500 }, 'test');

                mechanism.fail = (msg) => {
                    msg.should.equal('Got a request error StrataBasicAuth: TEST ERROR');
                    done();
                };

                mechanism.doRemoteCall('fdsafas');
            });
        });

        describe('buildUserObject', () => {
            const getInput = (override) => {
                return JSON.stringify(Object.assign(samples.strataUserObject, override));
            };

            it('should look like the standard user object', () => {
                const userObject = mechanism.buildUserObject(getInput());
                funcs.validateUser(userObject);
                userObject.should.have.property('is_active', true);
                userObject.should.have.property('is_org_admin', true);
                userObject.should.have.property('is_internal', true);
            });
        });
    });

    describe('keycloakJwt', () => {
        let mechanism;

        beforeEach(() => {

            // get a new one each time an it is run
            mechanism = new auth.keycloakJwt();
        });

        describe('doRemoteCall', () => {
            it('should fail() (quickly) when a bogus JWT is given', (done) => {
                mechanism.fail = (msg) => {
                    msg.should.equal('No username found in JWT: JsonWebTokenError: jwt malformed');
                    done();
                };
                mechanism.doRemoteCall('fdsfjkslfjsklfjjeiwjr4324', 'bogus');
            }).timeout(10);
        });

        describe('buildUserObject', () => {

            const getInput = (override) => {
                return Object.assign(samples.keycloakJwtUserObject, override);
            };

            it('should look like the standard user object', () => {
                const userObject = mechanism.buildUserObject(getInput());
                funcs.validateUser(userObject);
                userObject.should.have.property('is_org_admin', true);
                userObject.should.have.property('is_internal', true);
            });

            it('should handle Strings or Numbers', () => {
                const userObject = mechanism.buildUserObject(getInput({
                    account_number: 12345,
                    org_id: 54321
                }));
                funcs.validateUser(userObject);
            });

            it('should detect internal and org_admin being missing', () => {
                const userObject = mechanism.buildUserObject(getInput({
                    realm_access: { roles: ['foo'] }
                }));
                funcs.validateUser(userObject);
                userObject.should.have.property('is_org_admin', false);
                userObject.should.have.property('is_internal', false);
            });
        });
    });
});
