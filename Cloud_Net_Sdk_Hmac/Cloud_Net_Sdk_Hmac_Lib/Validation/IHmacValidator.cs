using Cloud_Net_Sdk_Hmac_Lib.Models;
using Microsoft.AspNetCore.Http;

namespace Cloud_Net_Sdk_Hmac_Lib.Validation
{
    public interface IHmacValidator
    {
        HmacValidationResult ValidateHttpRequest(HttpRequest request);
    }
}