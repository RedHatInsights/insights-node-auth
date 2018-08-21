/*global require, module*/
'use strict';

const config = require('../config');
const debug  = require('debug')('auth');
const cache  = require('../cache');
const priv   = {};

class Mechanism {
    constructor (req, deferred) {
        if (this.constructor === Mechanism) {
            throw new Error('Mechanism is the abstract class... you cant instantiate this');
        }

        priv.addAbstractMethods(this, ['buildUserObject', 'getCacheKey', 'ensureCredentials', 'getCreds', 'doRemoteCall']);

        this.useragent = 'access-insights-auth';
        this.req = req;
        this.deferred = deferred;
        this.config = config;
    }

    nullEmptyOrUndefined (str) {
        return (!str || str.trim() === '' || str === 'undefined');
    }

    shouldCache () {
        if (this.supportsCache === false || this.req.get('x-rh-shouldauthcache') === 'false') {
            return false;
        }

        return true;
    }

    tryAuth () {
        const instance = this;

        if (priv.alreadyAuthed(instance.req)) {
            return priv.pass(instance.deferred, instance.skipValue, 'skipping');
        }

        const creds = instance.getCreds(instance.req);

        // Pre flight test... exit early if not enough data
        try {
            instance.ensureCredentials(creds);
        } catch (e) {
            return instance.fail(e);
        }

        if (instance.shouldCache()) {

            // Try the cache
            const cacheKey = instance.getCacheKey(creds);
            cache.get(cacheKey, (user) => {

                // Exit if the user was in cache
                if (user && user.is_active) {
                    user.cachehit = true;
                    priv.pass(instance.deferred, user, `got authed user from cache:  ${user.sso_username}`);
                    return;
                }

                try {
                    instance.doRemoteCall(creds, (data) => {
                        priv.tryPassAndCache(instance, cacheKey, instance.buildUserObject(data));
                    });
                } catch (e) {
                    return instance.fail(e);
                }
            });
        } else {
            instance.doRemoteCall(creds, (data) => {
                priv.tryPassAndCache(instance, false, instance.buildUserObject(data));
            });
        }

        return instance.deferred.promise;
    }

    logger (msg) {
        if (msg) {
            debug(msg);
        }
    }

    fail (msg) {
        this.logger(msg);
        this.deferred.resolve({user: false, msg: msg});
        return this.deferred.promise;
    }

    get name () {
        return this.constructor.name;
    }

    get skipValue () {
        return 'SKIP';
    }
}

// Private functions

priv.addAbstractMethods = (that, names) => {
    names.forEach((name) => {
        if (that[name] === undefined) {
            throw new TypeError(`Must override method: ${name}`);
        }
    });
};

priv.alreadyAuthed = (req) => {
    return req.authorized;
};

priv.tryPassAndCache = (instance, cacheKey, user) => {

    if (!user) {
        return instance.fail('User object is null');
    }

    if (!user.sso_username) {
        return instance.fail('User object does not have a sso_username');
    }

    // if present add the cookie from upstream
    // if (apiResponse.headers['set-cookie']) {
    //     req.headers['set-cookie'] = apiResponse.headers['set-cookie'];
    // }

    user.cachehit = false;

    if (instance.shouldCache()) {
        debug(`${user.sso_username} setting cache`);

        // cache this  auth
        cache.set(cacheKey, user, () => {
            priv.pass(instance.deferred, user, `sucessful auth/cache for ${user.sso_username}`);
        });
    } else {
        priv.pass(instance.deferred, user, `sucessful auth for ${user.sso_username}`);
    }

    return instance.deferred.promise;
};

priv.pass = (deferred, user, msg) => {
    debug(msg);
    deferred.resolve({user: user, msg: msg});
    return deferred.promise;
};

module.exports = Mechanism;
