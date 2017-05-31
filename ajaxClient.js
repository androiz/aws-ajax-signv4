/*
config = {
    endpoint: "",
    secretKey: "",
    privateKey: "",
    sessionToken: "",
    apiKey: "",
    region: "",
    serviceName: ""
}

request = {
    verb: 'GET',
    path: '/path/',
    queryParams: {
        "query": "sevilla"
    },
    //body: undefined,
    headers: {
        "x-api-key": client.config.apiKey
    }
}

signedRequest = {
    method: verb,
    url: url,
    headers: headers,
    data: body
}

*/

var ajaxSignClient = {};
ajaxSignClient.newClient = function (config) {
    if(config === undefined) {
        config = {
            accessKey: '',
            secretKey: '',
            sessionToken: '',
            serviceName: '',
            region: '',
            apiKey: undefined,
            defaultContentType: 'application/json',
            defaultAcceptType: 'application/json',
            endpoint: ''
        };
    }
    if(config.accessKey === undefined) {
        config.accessKey = '';
    }
    if(config.secretKey === undefined) {
        config.secretKey = '';
    }
    if(config.apiKey === undefined) {
        config.apiKey = '';
    }
    if(config.sessionToken === undefined) {
        config.sessionToken = '';
    }
    if(config.region === undefined) {
        config.region = 'us-west-1';
    }
    //If defaultContentType is not defined then default to application/json
    if(config.defaultContentType === undefined) {
        config.defaultContentType = 'application/json';
    }
    //If defaultAcceptType is not defined then default to application/json
    if(config.defaultAcceptType === undefined) {
        config.defaultAcceptType = 'application/json';
    }
    if(config.invokeUrl === undefined) {
        config.invokeUrl = '';
    }
    if(config.serviceName === undefined) {
        config.serviceName = 'execute-api';
    }

    config.endpoint = /(^https?:\/\/[^\/]+)/g.exec(config.endpoint)[1];

    this.config = config;

    this.AWS_SHA_256 = 'AWS4-HMAC-SHA256';
    this.AWS4_REQUEST = 'aws4_request';
    this.AWS4 = 'AWS4';
    this.X_AMZ_DATE = 'x-amz-date';
    this.X_AMZ_SECURITY_TOKEN = 'x-amz-security-token';
    this.HOST = 'host';
    this.AUTHORIZATION = 'Authorization';

    this.hash = function (value) {
        return CryptoJS.SHA256(value);
    }

    this.hexEncode = function (value) {
        return value.toString(CryptoJS.enc.Hex);
    }

    this.hmac = function (secret, value) {
        return CryptoJS.HmacSHA256(value, secret, {asBytes: true});
    }

    this.buildCanonicalRequest = function (method, path, queryParams, headers, payload) {
        return method + '\n' +
            this.buildCanonicalUri(path) + '\n' +
            this.buildCanonicalQueryString(queryParams) + '\n' +
            this.buildCanonicalHeaders(headers) + '\n' +
            this.buildCanonicalSignedHeaders(headers) + '\n' +
            this.hexEncode(this.hash(payload));
    }

    this.hashCanonicalRequest = function (request) {
        return this.hexEncode(this.hash(request));
    }

    this.buildCanonicalUri = function (uri) {
        return encodeURI(uri);
    }

    this.buildCanonicalQueryString = function (queryParams) {
        if (Object.keys(queryParams).length < 1) {
            return '';
        }

        var sortedQueryParams = [];
        for (var property in queryParams) {
            if (queryParams.hasOwnProperty(property)) {
                sortedQueryParams.push(property);
            }
        }
        sortedQueryParams.sort();

        var canonicalQueryString = '';
        for (var i = 0; i < sortedQueryParams.length; i++) {
            canonicalQueryString += sortedQueryParams[i] + '=' + this.fixedEncodeURIComponent(queryParams[sortedQueryParams[i]]) + '&';
        }
        return canonicalQueryString.substr(0, canonicalQueryString.length - 1);
    }

    this.fixedEncodeURIComponent = function (str) {
      return encodeURIComponent(str).replace(/[!'()*]/g, function(c) {
        return '%' + c.charCodeAt(0).toString(16);
      });
    }

    this.buildCanonicalHeaders = function (headers) {
        var canonicalHeaders = '';
        var sortedKeys = [];
        for (var property in headers) {
            if (headers.hasOwnProperty(property)) {
                sortedKeys.push(property);
            }
        }
        sortedKeys.sort();

        for (var i = 0; i < sortedKeys.length; i++) {
            canonicalHeaders += sortedKeys[i].toLowerCase() + ':' + headers[sortedKeys[i]] + '\n';
        }
        return canonicalHeaders;
    }

    this.buildCanonicalSignedHeaders = function (headers) {
        var sortedKeys = [];
        for (var property in headers) {
            if (headers.hasOwnProperty(property)) {
                sortedKeys.push(property.toLowerCase());
            }
        }
        sortedKeys.sort();

        return sortedKeys.join(';');
    }

    this.buildStringToSign = function (datetime, credentialScope, hashedCanonicalRequest) {
        return this.AWS_SHA_256 + '\n' +
            datetime + '\n' +
            credentialScope + '\n' +
            hashedCanonicalRequest;
    }

    this.buildCredentialScope = function (datetime, region, service) {
        return datetime.substr(0, 8) + '/' + region + '/' + service + '/' + this.AWS4_REQUEST
    }

    this.calculateSigningKey = function (secretKey, datetime, region, service) {
        return this.hmac(this.hmac(this.hmac(this.hmac(this.AWS4 + secretKey, datetime.substr(0, 8)), region), service), this.AWS4_REQUEST);
    }

    this.calculateSignature = function (key, stringToSign) {
        return this.hexEncode(this.hmac(key, stringToSign));
    }

    this.buildAuthorizationHeader = function (accessKey, credentialScope, headers, signature) {
        return this.AWS_SHA_256 + ' Credential=' + accessKey + '/' + credentialScope + ', SignedHeaders=' + this.buildCanonicalSignedHeaders(headers) + ', Signature=' + signature;
    }

    return this;
}

ajaxSignClient.ajaxSignedRequest = function(request) {
    var verb = request.verb;
    var path = request.path;
    var queryParams = request.queryParams;
    if (queryParams === undefined) {
        queryParams = {};
    }
    var headers = request.headers;
    if (headers === undefined) {
        headers = {};
    }

    //If the user has not specified an override for Content type the use default
    if(headers['Content-Type'] === undefined) {
        headers['Content-Type'] = this.config.defaultContentType;
    }

    //If the user has not specified an override for Accept type the use default
    if(headers['Accept'] === undefined) {
        headers['Accept'] = this.config.defaultAcceptType;
    }

    var body = request.body;
    if (body === undefined || verb === 'GET') { // override request body and set to empty when signing GET requests
        body = '';
    }  else {
        body = JSON.stringify(body);
    }

    //If there is no body remove the content-type header so it is not included in SigV4 calculation
    if(body === '' || body === undefined || body === null) {
        delete headers['Content-Type'];
    }

    var datetime = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z').replace(/[:\-]|\.\d{3}/g, '');
    headers[this.X_AMZ_DATE] = datetime;
    var parser = document.createElement('a');
    parser.href = this.config.endpoint;
    headers[this.HOST] = parser.hostname;

    var canonicalRequest = this.buildCanonicalRequest(verb, path, queryParams, headers, body);
    var hashedCanonicalRequest = this.hashCanonicalRequest(canonicalRequest);
    var credentialScope = this.buildCredentialScope(datetime, this.config.region, this.config.serviceName);
    var stringToSign = this.buildStringToSign(datetime, credentialScope, hashedCanonicalRequest);
    var signingKey = this.calculateSigningKey(this.config.secretKey, datetime, this.config.region, this.config.serviceName);
    var signature = this.calculateSignature(signingKey, stringToSign);

    headers[this.AUTHORIZATION] = this.buildAuthorizationHeader(this.config.accessKey, credentialScope, headers, signature);

    if(this.config.sessionToken !== undefined && this.config.sessionToken !== '') {
        headers[this.X_AMZ_SECURITY_TOKEN] = this.config.sessionToken;
    }
    delete headers[this.HOST];

    var url = this.config.endpoint + path;
    var queryString = this.buildCanonicalQueryString(queryParams);
    if (queryString != '') {
        url += '?' + queryString;
    }

    //Need to re-attach Content-Type if it is not specified at this point
    if(headers['Content-Type'] === undefined) {
        headers['Content-Type'] = this.config.defaultContentType;
    }

    var signedRequest = {
        method: verb,
        url: url,
        headers: headers,
        data: body
    };

    return signedRequest;
}
