using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Cloud_Net_Sdk_Hmac_Client.Models;
using Cloud_Net_Sdk_Hmac_Lib.Models;
using Cloud_Net_Sdk_Hmac_Lib.Signers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Cloud_Net_Sdk_Hmac_Client.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        private readonly IConfigurationRoot _configuration;
        private string _cLientId = "";
        private string _clientSecret = "";
        private string _authUrl = "";

        public ValuesController(IConfigurationRoot configuration)
        {
            _configuration = configuration;
            _cLientId = configuration["HMAC_KEY_CONFIG:clientId"];
            _clientSecret = configuration["HMAC_KEY_CONFIG:clientSecret"];
            _authUrl = configuration["AppSettings:proxyUrl"];
        }

        [AllowAnonymous]
        ///Test post to /authz/v1/oauth/verifytoken
        [HttpGet("TestPost")]
        public JsonResult PostAsync()
        {
            try
            {
                var endpointUri = _authUrl + "/authz/v1/oauth/verifytoken";
                var restApi = new RestApiHmac<object>();
                ModelRequest request = new ModelRequest()
                {
                    Id = "1",
                    Name = "Name1"
                };
                var result = restApi.DoRequestV2(HttpMethod.POST, endpointUri, _cLientId, _clientSecret, request, null);
                return new JsonResult(result);
            }
            catch (Exception e)
            {
                return new JsonResult(e.Message);
            }
        }

        ///Test get to /authz/v1/oauth/verifytoken/123456?param=12134
        [HttpGet("TestGet")]
        public JsonResult GetAsync()
        {
            try
            {
                var endpointUri = _authUrl + "/address/v2/Location/Regions";
                var restApi = new RestApiHmac<object>();
                var result = restApi.DoRequestV2(HttpMethod.GET, endpointUri, _cLientId, _clientSecret, null);
                return new JsonResult(result);
            }
            catch (Exception e)
            {
                return new JsonResult(e.Message);
            }
        }

        ///Test get to /authz/v1/oauth/verifytoken/123456?param=12134
        [HttpGet("TestGetOldResponse")]
        public JsonResult TestGetOldResponse()
        {
            try
            {
                var endpointUri = _authUrl + "/authz/v1/oauth/verifytoken-old/1";
                var restApi = new RestApiHmac<object>();
                var result = restApi.DoRequestV1(HttpMethod.GET, endpointUri, _cLientId, _clientSecret, null);
                return new JsonResult(result);
            }
            catch (Exception e)
            {
                return new JsonResult(e.Message);
            }
        }

        ///Test detele to authz/v1/oauth/verifytoken/123456
        [HttpGet("TestDelete")]
        public JsonResult Delete()
        {
            try
            {
                var endpointUri = _authUrl + "/authz/v1/oauth/verifytoken/123456";
                var restApi = new RestApiHmac<string>();
                var result = restApi.DoRequestV2(HttpMethod.DELETE, endpointUri, _cLientId, _clientSecret);
                return new JsonResult(result);
            }
            catch (Exception e)
            {
                return new JsonResult(e.Message);
            }
        }

        ///Test Put to /authz/v1/oauth/verifytoken/123456
        [HttpGet("TestPut")]
        public JsonResult Put()
        {
            try
            {
                var endpointUri = _authUrl + "/authz/v1/oauth/verifytoken/123456";
                var restApi = new RestApiHmac<ModelRequest>();
                ModelRequest request = new ModelRequest()
                {
                    Id = "1",
                    Name = "Name1"
                };
                var result = restApi.DoRequestV1(HttpMethod.PUT, endpointUri, _cLientId, _clientSecret, request, null);
                return new JsonResult(result);
            }
            catch (Exception e)
            {
                return new JsonResult(e.Message);
            }
        }
    }

}