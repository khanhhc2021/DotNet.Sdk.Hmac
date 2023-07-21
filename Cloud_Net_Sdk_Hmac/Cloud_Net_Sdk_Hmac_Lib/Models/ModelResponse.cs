using System;
using System.Net;
using System.Xml;

namespace Cloud_Net_Sdk_Hmac_Lib.Models
{

    public class ModelResponse<T>
    {
        public ApiResponse<T> NewResponse { get; set; }
        public ApiJsonResultData<T> OldResponse { get; set; }
    }
}