/*global module, require, process*/
'use strict';

const pubkey_utils = require('./utils/pubkey-utils');

// this is a backup of the prod pubkey
// to be used in fall back situations
const ssoPubKey = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuYp35gi5YzQeNN5aQOPwLranSJT9aJB+w6Ih
4Wn9R6FzEg1OEKwBNNpb+z18reAyhxQMy/bCz3q+J7viX6p5hbclPBakKOjPB4lDzwhvfE1G4vp84zH1
bR7m8dd4OXbriojVZ51IPNuItO00nrDrx6PWNP/5ufBUwjJo8+BD+sWm7BP/CVlb8miVh8itpcLJrszp
HzF+u0OPqwI/e3P83cYOsXoQRxD4wpo718yqYh4J3NNJQYnyprJMpC3w3QQ5PR28TbBfSHgvtWD1SBua
vHh2jwT/6Pi8FqOS1vfX7QA1pxyYZ+zazVxj/zOrCeP3FHyaxTPmn0d5zsXBZCCyhsfCaStnFePTPk+K
EGwZAlv43JJjV2rTJc1Lsj1Th7Jq63TvwIGBcFFAtC72N5+jwRjUoeyu/nwO/1r1awvbfrlBF31PG5wx
UdVR56PesLO7EVH1/2KrVN7dtgaQkomVk6rULBbCbwhfR1oT3cOxF7d0ajpbzHd2qcfeBzFTABL8dzBp
4FcZx5QyYSIOP8fuwSO8zy4rxmBw7HpHGOGFrC3cXWqB33M23IjOpVZbfK46QvJhcGq9QEtOlRO2WVem
McwDSgpceAa7e3ZJx+LO6XyTEjRtTuHMwdLxII3YUlL1hPozrNE1U/ADPGHgnTxGswgBpGOA6rOkWav5
uhcj9CsCAwEAAQ==
-----END PUBLIC KEY-----`;

const config = {
    strataAuthUrl: process.env.STRATA_AUTH_URL || 'https://access.redhat.com/rs/users/current',
    middlewareHost: process.env.MIDDLEWARE_HOST,
    phxproxyToken: process.env.PHXPROXY_TOKEN,
    ssoPubKey: ssoPubKey,
    requestOptions: {
        strictSSL: ((process.env.STRICT_SSL === 'false') ? false : true),
        headers: {
            Accept: 'application/json'
        }
    }
};

if (process.env.NODE_ENV !== 'test') {
    config.ssoPubKey = pubkey_utils.fetch() || ssoPubKey;
}

module.exports = config;
