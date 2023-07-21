using System;
namespace Cloud_Net_Sdk_Hmac_Lib.Models
{
    public class AuthorizationModel
    {
        public string Host { get; set; }
        public string CanonicalRequest { get; set; }
        public string StringToSign { get; set; }
        public string Signature { get; set; }
        public string Credential { get; set; }
        public string SignedHeaders { get; set; }
        public string Authorization { get; set; }
    }
}