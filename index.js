'use strict';
var jsonwebtoken = require('jsonwebtoken');

var publicSertificate = '-----BEGIN CERTIFICATE-----\n' +
    'YOUR_PUBLIC_SERTIFICATE_FROM_KEYCLOAK\n' +
    '-----END CERTIFICATE-----';

const unauthorizedResponse = {
    status: 401,
    statusDescription: 'Unauthorized',
    headers: {
        "content-type": [{
            "key": "Content-Type",
            "value": "application/json; charset=utf-8"
        }]
    },
    body: '{\n' +
        '"timestamp": ' + new Date().toString() +',\n' +
        '"status": 401,\n' +
        '"error": "Unauthorized",\n' +
        '"path": "/images"\n' +
        '}\n'.toString()
};

exports.handler = async(event, context, callback) => {
    const cfRequest = event.Records[0].cf.request;
    const url = cfRequest.uri;
    let formattedAuthorizationToken = null;

    try {
        formattedAuthorizationToken = cfRequest.headers['authorization'][0].value.replace('Bearer ', '');
    }
    catch (e) {
        console.log('Error reading jwt token from request. Error: ' + e.message);
        callback(null, unauthorizedResponse);
    }


    console.log('TOKEN');
    console.log(formattedAuthorizationToken);

    console.log('CHECK TOKEN ATTEMPT');

    jsonwebtoken.verify(formattedAuthorizationToken, publicSertificate, { algorithms: ['RS256'] }, function(err, decoded) {

        if (err !== null && typeof(err) !== "undefined") {
            if (err.name === 'TokenExpiredError') {
                console.log('[' + formattedAuthorizationToken + ']\n' + '\ntoken error --> [' + err.message + ' ' + err.expiredAt + ']');
            }

            if (err.name === 'JsonWebTokenError') {
                console.log('[' + formattedAuthorizationToken + ']\n' + '\ntoken error --> [' + err.message + ']');
            }

            callback(null, unauthorizedResponse);
        }

        if(url.includes("AVATAR") || url.includes("SKIN_SCAN")) {
            if(!url.includes(jsonwebtoken.decode(formattedAuthorizationToken).sub)) {
                callback(null, unauthorizedResponse);
            }
        }

        console.log(decoded);
        callback(null, cfRequest);
    });

};
