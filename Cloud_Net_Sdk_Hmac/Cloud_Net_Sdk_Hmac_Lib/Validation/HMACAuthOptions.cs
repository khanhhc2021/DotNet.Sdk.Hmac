using Microsoft.AspNetCore.Authentication;

namespace Cloud_Net_Sdk_Hmac_Lib.Validation
{
    public class HMACAuthOptions : AuthenticationSchemeOptions
    {
        public const string Scheme = "HmacAuthentication";
    }
}