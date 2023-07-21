# DotNet HMAC Authentication

DotNet HMAC Authentication is a library using for server Authentication HTTP Header and client signing header request. This algorithm base on AWS4 HMAC Authentication.

## Installation

Support for dot net core only,  version >= 2.2

```bash
Install-Package Cloud.Net.Sdk.Hmac
OR
dotnet add package Cloud.Net.Sdk.Hmac
```

## Usage
Authentication

```bash
Startup.cs
public void ConfigureServices(IServiceCollection services)
{
 //..           
 services.AddAuthentication(HMACAuthOptions.Scheme).AddScheme<HMACAuthOptions, CustomAuthHandler>(HMACAuthOptions.Scheme, null);
 //..          
}
public void Configure(IApplicationBuilder app, IHostingEnvironment env)
{
  //..
  app.UseAuthentication(); 
  app.Use(next => context => { context.Request.EnableRewind(); return next(context); });
  //..
}

ApiController.cs
[Authorize(AuthenticationSchemes = HMACAuthOptions.Scheme)]
[HttpGet]  
public ActionResult<IEnumerable<string>> Get()
{
   //..
}

appsettings.json add this config
"HMAC_KEY_CONFIG": {
        "ClientId": "8bf49c695244120399b2c5a00cdbdb9b",
        "SecretKey": "1f48072533be925008777c618c71d492de0294f8"
    }
```

Signer

```bash
   var endpointUri = "https://domaintest.vn/authz/v1/oauth/verifytoken/1";
   var restApi = new RestApiHmac<object>();
   var result = restApi.DoRequestV2(HttpMethod.GET, endpointUri, _cLientId, _clientSecret, null);
```

Use Mothod DoRequestV1 if you want response format:

```bash
   public class ApiJsonResultData<T>
    {
        public bool Success { get; set; }
        public T Data { get; set; }
        public string ErrorMessage { get; set; }
    }
```

Use Mothod DoRequestV2 if you want response format:
```bash
    public class ApiResponse<T>
    {
        public string Code { get; set; }
        public string Message { get; set; }
        public T Data { get; set; }
        public TokenMetaDataVerifyResponse Metadata { get; set; }
    }
```


## Soure description

Project core: Cloud_Net_Sdk_Hmac_Lib
Project for testing: Cloud_Net_Sdk_Hmac_Api and Cloud_Net_Sdk_Hmac_Client

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## Requirements
The connecting client must have possession of the following credentials: 
Client ID
Client Secret 
Resource Server URL
The credentials are provided to developers by the system administrator.
The requesting client’s Client ID and Client Secret must be configured on the resource server that is authenticating the HMAC request. 
The requesting client must be able to make HTTP requests using a User Agent.
The requesting client must be able to add request headers to User Agent HTTP requests.


## Reference
Based on AWS Authorization
The HMAC authentication protocol very closely follows the Amazon Web Services “AWS Authorization” and “AWS Signature Version 4” protocols.

For further implementation examples, refer to the AWS documentation:
Authorization Header:
http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html
Authorization Signature:
http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
AWS Signature Calculation Diagram:

![alt text](https://i.ibb.co/CWWQyx4/Screenshot-2023-07-21-at-17-10-25.png)

##Other References
https://www.okta.com/identity-101/hmac/#:~:text=Hash%2Dbased%20message%20authentication%20code,use%20signatures%20and%20asymmetric%20cryptography
https://docs.microsoft.com/en-us/azure/azure-app-configuration/rest-api-authentication-hmac



## License
huynhkhanh1809@gmail.com