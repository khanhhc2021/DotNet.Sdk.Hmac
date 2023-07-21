using System;
using System.Net;
using System.Xml;

namespace Cloud_Net_Sdk_Hmac_Lib.Models
{
    public class ApiResponse<T>
    {
        public string Code { get; set; }
        public string Message { get; set; }
        public T Data { get; set; }
        public TokenMetaDataVerifyResponse Metadata { get; set; }
        public ApiResponse(HttpStatusCode statusCode, string data)
        {
            Code = Convert.ToString((int) statusCode);
            Message = statusCode.ToString();
            Data = GetValue<T>(data);
        }
        public ApiResponse(string data)
        {
            Code = "";
            Message = "";
            Data = GetValue<T>(data);
        }
        public ApiResponse() { }
        private T GetValue<TValue>(string value)
        {
           try {
               return (T) Convert.ChangeType(value, typeof(T));
            }
            catch(Exception){
                return default(T);
            }
        }
    }

    public class ApiResponseData
    {
        public string Code { get; set; }
        public string Message { get; set; }
        public object Data { get; set; }
        public TokenMetaDataVerifyResponse Metadata { get; set; }
    }
}