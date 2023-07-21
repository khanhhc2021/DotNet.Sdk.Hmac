using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Cloud_Net_Sdk_Hmac_Lib.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Internal;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Cloud_Net_Sdk_Hmac_Lib.Validation
{
    public class CustomAuthHandler : AuthenticationHandler<HMACAuthOptions>
    {
        private IHmacValidator _hmacValidator;
        private IConfigurationRoot _configuration;
        public CustomAuthHandler(
            IOptionsMonitor<HMACAuthOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            IConfigurationRoot configuration,
            ISystemClock clock) : base(options, logger, encoder, clock)
        {
            _configuration = configuration;
            _hmacValidator = new HmacValidator(_configuration);
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {   
            if (string.IsNullOrEmpty(Request.Headers["X-Authorization"]))
               return   AuthenticateResult.Fail("Unauthorized");
            Request.EnableRewind();
            HmacValidationResult validResult = _hmacValidator.ValidateHttpRequest(Request);
            Debug.WriteLine("VALIDATE-RESULT: " + validResult.ErrorMessage);
            if (validResult.ResultCode != HmacValidationResultCode.Ok)
                return   AuthenticateResult.Fail(validResult.ErrorMessage);
            var identities = new List<ClaimsIdentity> { new ClaimsIdentity("custom auth type") };
            var ticket = new AuthenticationTicket(new ClaimsPrincipal(identities), HMACAuthOptions.Scheme);
            return AuthenticateResult.Success(ticket);
        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            await base.HandleChallengeAsync(properties);
        }

    }
}