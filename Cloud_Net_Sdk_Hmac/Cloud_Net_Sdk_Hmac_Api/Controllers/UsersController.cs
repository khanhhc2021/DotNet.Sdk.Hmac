using System;
using System.Collections.Generic;
using Cloud_Net_Sdk_Hmac_Api.Models;
using Cloud_Net_Sdk_Hmac_Lib.Models;
using Cloud_Net_Sdk_Hmac_Lib.Validation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Cloud_Net_Sdk_Hmac_Api.Controllers
{
    [Route("/")]
    [ApiController]
    public class UsersController : ControllerBase
    {

        //  GET api/values
        //  [Authorize(AuthenticationSchemes = HMACAuthOptions.Scheme)]
        [HttpGet]
        public ActionResult<IEnumerable<string>> Get()
        {
            return new string[] { "value1", "value2" };
        }

        [Authorize(AuthenticationSchemes = HMACAuthOptions.Scheme)]
        //[AllowAnonymous]
        [HttpGet("authz/v1/oauth/verifytoken/{id}")]
        public ApiResponse<ModelRequest> Get(string id)
        {
            ModelRequest request = new ModelRequest()
            {
                Id = "1",
                    Name = "Name1"
            };
            return new ApiResponse<ModelRequest>
            {
                Code = "200",
                Message = "OK",
                Data = request
            };
        }

        [Authorize(AuthenticationSchemes = HMACAuthOptions.Scheme)]
        [HttpPost("authz/v1/oauth/verifytoken")]
        public ApiResponse<ModelRequest> Post([FromBody] ModelRequest values)
        {
            return new ApiResponse<ModelRequest>
            {
            Code = "200",
            Message = "OK",
            Data = values
            };
        }

        [HttpGet("authz/v1/oauth/verifytoken-old/{id}")]
        public ApiJsonResultData GetOldResponse(string id)
        {
            ModelRequest request = new ModelRequest()
            {
                Id = "1",
                Name = "Name1"
            };
            return new ApiJsonResultData(true, request);
        }
    }
}