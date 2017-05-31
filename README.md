# aws-ajax-signv4
Library for signing ajax request

## Usage
First we have to initialize the client with the AWS user credentials:

```javascript
// Initialization
var signclient = ajaxSignClient.newClient({
    accessKey: '<accessKey>',
    secretKey: '<secretKey>',
    sessionToken: '',
    serviceName: '',
    region: '<region>',
    apiKey: '<apiKey>',
    endpoint: '<endpoint>'
    // defaultContentType: 'application/json'
    // defaultAcceptType: 'application/json'
});
```

Then we have to create the signed request using the client:

```javascript
// Signing Request
var signedRequest = signclient.ajaxSignedRequest(
    {
        verb: 'GET',
        path: '/path/',
        queryParams: {
            "query": "Sevilla"
        },
        body: {},
        headers: {
            "x-api-key": signclient.config.apiKey
        }
    }
);
```

Finally, we can build the ajax call using our signedRequest:

```javascript
// Performing request
$.ajax({
    url: signedRequest.url,
    type: signedRequest.method,
    dataType: 'json',
    data: signedRequest.data,
    headers: signedRequest.headers,
    success: function (data, status, request) {
        console.log(data);
    },
    failure: function () {
        console.log("error");
    }
});
```


Further information don't hesitate of contact me to [androiz10@gmail.com](mailto:androiz10@gmail.com).