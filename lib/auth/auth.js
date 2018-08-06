/*global module, require, process*/
'use strict';

const Q     = require('bluebird');
const debug = require('debug')('auth');
const priv  = {};

module.exports.smwBasic          = require('./mechanisms/smw-basic');
module.exports.strataBasic       = require('./mechanisms/strata-basic');
module.exports.keycloakJwt       = require('./mechanisms/keycloak-jwt');
module.exports.cert              = require('./mechanisms/cert');
module.exports.systemid          = require('./mechanisms/systemid');
module.exports.config            = require('./config');
module.exports.updateCacheClient = (client) => {
    require('./cache').updateClient(client, true);
};

priv.validateAccountNumber = (input) => {
    if (!input) { return false; }
    if (input === null) { return false; }
    return !Number.isNaN(Number(input));
};

priv.validateUser = (user, skipValue) => {
    return (user === skipValue) || (user && user.is_active && priv.validateAccountNumber(user.account_number));
};

module.exports.execChain = (app, mechanisms, deferred) => {
    if (!Array.isArray(mechanisms)) {
        throw new Error(`Passed in mechanisms array is not an array O_o : ${mechanisms}`);
    }

    mechanisms.forEach((passedInMechanism, i) => {
        if (!passedInMechanism) {
            throw new Error(`Invalid auth mechanism passed in: ${passedInMechanism}`);
        }

        app.use((req, res, next) => {
            const mechanism = new passedInMechanism(req, Q.defer());
            debug(`doing ${mechanism.name}`);

            mechanism.tryAuth().then((ret) => {
                if (!priv.validateUser(ret.user, mechanism.skipValue)) {
                    debug(`${mechanism.name}: failed`);
                    if (i === (mechanisms.length - 1)) {
                        debug(`${mechanism.name} was the last mechanism... giving up now`);

                        if (!ret.user) {
                            if (deferred) { deferred.reject(401); }
                            return res.status(401).end();
                        }

                        if (!ret.user.is_active) {
                            if (deferred) { deferred.reject(403); }
                            return res.status(403).json({
                                message: 'Forbidden: user is not active'
                            });
                        }

                        if (!priv.validateAccountNumber(ret.user.account_number)) {
                            if (deferred) { deferred.reject(402); }
                            return res.status(402).json({
                                message: 'No Red Hat account found'
                            });
                        }

                        // Dunno why we would get here, but fail anyway
                        return res.status(403).json({
                            message: 'Auth failed, in an unexpected way'
                        });
                    }
                    return next(); // try the next auth mechanism
                }

                if (ret.user !== mechanism.skipValue) {
                    ret.user.mechanism = mechanism.name;
                    req.authorized = ret.user;
                }

                if (deferred) { deferred.resolve(ret.user); }

                debug(ret.user);

                return next();
            }).catch((e) => {
                debug(`While running execChain with mechanism ${mechanism.name} caught ${e}`);
            });
        });
    });
};
