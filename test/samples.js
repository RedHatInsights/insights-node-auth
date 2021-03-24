/*global module*/

const pub = {
    accountNumber: '12345',
    orgId: '54321',
    locale: 'en_US',
    ssoUsername: 'bob-loblaws-law-blog',
    email: 'bobloblaw@example.com',
    firstName: 'Bob',
    lastName: 'Lowlaw',
    timezone: 'America/Los_Angeles',
    company: 'Bob Loblaw Attourney At Law',
    phoneNumber: '000.000.0000',
    address: {
        street: 'Bob Lane',
        county: 'ORANGE',
        countryCode: 'US',
        poBox: false,
        postalCode: '92663',
        state: 'CA',
        city: 'NEWPORT BEACH'
    }
};

module.exports.pub = pub;

module.exports.certUserObject =  {
    user: {
        id: 123456,
        username: 'bob-loblaws-law-blog',
        email: 'bobloblaw@example.com',
        first_name: 'Bob',
        last_name: 'Lowlaw',
        account_number: '12345',
        address_string: '"Bob Lowlaw" bobloblaw@example.com',
        is_active: true,
        is_org_admin: true,
        is_internal: false,
        locale: 'en_US',
        org_id: '54321',
        type: 'satellite'
    },
    cn: 'EAD1738838838',
    mechanism: 'cert'
};

module.exports.smwBasicUserObject = {
    user: {
        id: 123456,
        username: 'bob-loblaws-law-blog',
        email: 'bobloblaw@example.com',
        first_name: 'Bob',
        last_name: 'Lowlaw',
        account_number: '12345',
        address_string: '"Bob Lowlaw" bobloblaw@example.com',
        is_active: true,
        is_org_admin: true,
        is_internal: true,
        locale: 'en_US',
        org_id: '54321'
    },
    mechanism: 'basic'
};

module.exports.strataUserObject = {
    user: {
        id: 123456,
        username: 'bob-loblaws-law-blog',
        email: 'bobloblaw@example.com',
        first_name: 'Bob',
        last_name: 'Lowlaw',
        account_number: '12345',
        address_string: '"Bob Lowlaw" bobloblaw@example.com',
        is_active: true,
        is_org_admin: true,
        is_internal: true,
        locale: 'en_US',
        org_id: '54321'
    },
    mechanism: 'cert'
};

module.exports.keycloakJwtUserObject = {
    jti: '02729fd0-ed5f-4c86-9e32-11b26d564fds',
    exp: 1493740224,
    nbf: 0,
    iat: 1493739924,
    iss: 'https://sso.redhat.com/auth/realms/redhat-external',
    aud: 'customer-portal',
    sub: '9sdf1fdsfsdc-b593-4530-9428-7e7de3a9c65d',
    typ: 'Bearer',
    azp: 'customer-portal',
    session_state: 'fdsfs5e-7c62-4851-9a5d-e9a8fd0efdsfs',
    client_session: 'fdsfsdffd44-409a-482d-b57f-2b48fdsfs95f3',
    'allowed-origins': [
        'https://access.us.redhat.com',
        'https://hardware.redhat.com',
        'https://prod.foo.redhat.com:1337',
        'https://rhn.redhat.com',
        'https://www.redhat.com',
        'https://prod-mclayton.usersys.redhat.com',
        'https://access.redhat.com'
    ],
    realm_access: {
        roles: [
            'authenticated',
            'redhat:employees',
            'idp_authenticated',
            'portal_manage_subscriptions',
            'admin:org:all',
            'cservice',
            'portal_manage_cases',
            'portal_system_management',
            'cloud_access_1',
            'portal_download'
        ]
    },
    resource_access: {},
    REDHAT_LOGIN: pub.ssoUsername,
    lastName: pub.lastName,
    country: pub.address.countryCode,
    account_number: pub.accountNumber,
    employeeId: pub.ssoUsername,
    firstName: pub.firstName,
    account_id: pub.orgId,
    user_id: '59fdsf',
    organization_id: '0fsdfsdsdf000116C',
    siteId: 'redhat',
    siteID: 'redhat',
    portal_id: '0fdsfsd',
    lang: pub.locale,
    region: pub.address.countryCode,
    RHAT_LOGIN: pub.ssoUsername,
    email: pub.email,
    username: pub.ssoUsername,
    DONT_CACHE: true
};
