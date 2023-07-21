using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Cloud_Net_Sdk_Hmac_Lib.Models;
using Cloud_Net_Sdk_Hmac_Lib.Signers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Configuration;

namespace Cloud_Net_Sdk_Hmac_Lib.Validation
{
    public class HmacValidator : IHmacValidator
    {
        private const string _dateHeader = "x-tpa-date";
        private double _maxRequestAge = 300;
        private TimeSpan _maxRequestAgeTimeSpan;
        private const string _authorizationHeader = "X-Authorization";
        private const string _authorizationHeaderHMACSchema = "TPA-HMAC-SHA256";
        private HmacKeyConfig _hmacConfigKey;
        private IConfigurationRoot _configuration;
        public static HashAlgorithm _canonicalRequestHashAlgorithm = HashAlgorithm.Create("SHA-256");
        private int _minNumberOfHeaders = 4;
        public HmacValidator(IConfigurationRoot configuration)
        {
            _maxRequestAgeTimeSpan = TimeSpan.FromSeconds(_maxRequestAge);
            _configuration = configuration;
            _hmacConfigKey = _configuration.GetSection("HMAC_KEY_CONFIG").Get<HmacKeyConfig>();
        }

        #region support methods
        private static void WriteDownHeaderDataToConsole(IHeaderDictionary headers)
        {
            foreach (var header in headers)
            {
                Debug.WriteLine("REQUEST-HEADER:  " + header.Key + ": " + header.Value);
            }
        }

        /// <summary>
        /// Validates a datetime of a request according to the HMAC configuration that is used.
        /// </summary>
        /// <param name="dateTime">The datetime to validate.</param>
        /// <returns><c>true</c> if valid; otherwise, <c>false</c>.</returns>
        private bool IsValidRequestDate(DateTime dateTime)
        {
            if (dateTime.Kind == DateTimeKind.Local)
                dateTime = dateTime.ToUniversalTime();
            System.Globalization.CultureInfo.CurrentCulture.ClearCachedData();
            DateTime currentDateTime = DateTime.UtcNow;
            return currentDateTime <= dateTime.Add(_maxRequestAgeTimeSpan);
        }

        /// <summary>
        /// Validates a datetime offset of a request according to the HMAC configuration that is used.
        /// </summary>
        /// <param name="dateTimeOffset">The datetime offset to validate.</param>
        /// <returns><c>true</c> if valid; otherwise, <c>false</c>.</returns>
        private bool IsValidRequestDate(DateTimeOffset dateTimeOffset)
        {
            return IsValidRequestDate(dateTimeOffset.UtcDateTime);

        }

        private class DateTimeOffsetHelper
        {
            public static DateTimeOffset FromString(string offsetString)
            {

                DateTimeOffset offset;
                if (!DateTimeOffset.TryParse(offsetString, out offset))
                {
                    offset = DateTimeOffset.Now;
                }

                return offset;
            }
        }

        private string GetPathResources(string path)
        {
            if (string.IsNullOrEmpty(path)) return string.Empty;
            var regex = new Regex("^/v\\d+/(?<path>[\\w\\d._%-]+)(/|$)(?<path1>[\\w\\d._%-]+)?(/|$)(?<path2>[\\w\\d._%-]+)?");
            var match = regex.Match(path);
            if (match.Success == false)
            {
                regex = new Regex("^/(?<path>[\\w\\d._%-]+)(/|$)");
                match = regex.Match(path);
                if (match.Success == false) return string.Empty;
            }
            var result = match.Groups["path2"].Success ? match.Groups["path1"] : match.Groups["path"];
            return result.Value;
        }

        private static string ToHexString(byte[] data, bool lowercase)
        {
            var sb = new StringBuilder();
            for (var i = 0; i < data.Length; i++)
            {
                sb.Append(data[i].ToString(lowercase ? "x2" : "X2"));
            }
            return sb.ToString();
        }
        #endregion

        public HmacValidationResult ValidateHttpRequest(HttpRequest request)
        {
            WriteDownHeaderDataToConsole(request.Headers);

            if (request.Headers == null)
                return new HmacValidationResult(HmacValidationResultCode.RequestIsNull, "The request is null.");

            if (string.IsNullOrEmpty(request.Headers[_dateHeader]))
                return new HmacValidationResult(HmacValidationResultCode.DateMissing, "The request date was not found.");

            var tpaDateHeaderAsDateTimeOffset = DateTimeOffsetHelper.FromString(request.Headers[_dateHeader]);

            if (!IsValidRequestDate(tpaDateHeaderAsDateTimeOffset))
                return new HmacValidationResult(HmacValidationResultCode.DateInvalid, "The request date is invalid.");

            if (string.IsNullOrEmpty(request.Headers[_authorizationHeader]))
                return new HmacValidationResult(HmacValidationResultCode.AuthorizationMissing, "Authorization was not found.");

            string[] authorizationHeaderSplitedValues = request.Headers[_authorizationHeader].ToString().Split(" ");

            if (authorizationHeaderSplitedValues.Length < _minNumberOfHeaders)
                return new HmacValidationResult(HmacValidationResultCode.AuthorizationInvalid, "Authorization is invalid.");

            string authorizationSchema = authorizationHeaderSplitedValues[0];
            string authorizationCredential = authorizationHeaderSplitedValues[1];
            string authorizationSignedHeaders = authorizationHeaderSplitedValues[2].Replace("SignedHeaders=", "").Replace(",", "");
            string authorizationSignature = authorizationHeaderSplitedValues[3];

            if (string.IsNullOrEmpty(authorizationSchema))
                return new HmacValidationResult(HmacValidationResultCode.AuthorizationInvalid, "Authorization is invalid.");

            if (string.IsNullOrEmpty(authorizationCredential))
                return new HmacValidationResult(HmacValidationResultCode.AuthorizationInvalid, "Authorization is invalid.");

            if (authorizationSchema != _authorizationHeaderHMACSchema)
                return new HmacValidationResult(HmacValidationResultCode.AuthorizationInvalid, "Authorization is invalidd.");

            authorizationCredential = authorizationCredential.Replace(",", "");

            if (string.IsNullOrEmpty(authorizationCredential))
                return new HmacValidationResult(HmacValidationResultCode.AuthorizationInvalid, "Authorization is invalid.");

            string[] headerCredentialSplit = authorizationCredential.Split("/");

            if (headerCredentialSplit.Length == 0)
                return new HmacValidationResult(HmacValidationResultCode.AuthorizationInvalid, "Authorization is invalid.");

            string headerCLientIdSplit = headerCredentialSplit[0];

            if (string.IsNullOrEmpty(headerCLientIdSplit))
                return new HmacValidationResult(HmacValidationResultCode.AuthorizationInvalid, "Authorization is invalid.");

            headerCLientIdSplit = headerCLientIdSplit.Replace("Credential=", "");

            if (headerCLientIdSplit != _hmacConfigKey.ClientId)
                return new HmacValidationResult(HmacValidationResultCode.ClientIdNotFound, "ClientId Notfound.");

            string clientSecretkey = _hmacConfigKey.SecretKey;

            if (string.IsNullOrEmpty(clientSecretkey))
                return new HmacValidationResult(HmacValidationResultCode.KeyMissing, "Secretkey Missing.");

            if (string.IsNullOrEmpty(authorizationSignature))
                return new HmacValidationResult(HmacValidationResultCode.SignatureMismatch, "Signature Mismatch.");

            authorizationSignature = authorizationSignature.Replace("Signature=", "");

            var signer = new SignerForAuthorizationHeader
            {
                EndpointUri = new Uri(request.GetDisplayUrl()),
                HttpMethod = request.Method.ToUpper(),
                Service = null,
                Region = null,
            };
            Debug.WriteLine("HOST-REUQEST: " + signer.EndpointUri);
            Debug.WriteLine("Method: " + request.Method.ToUpper());
            Dictionary<string, string> requestHeaders = request.Headers.ToDictionary(a => a.Key.ToLower(), a => a.Value.ToString());
            var signedHeadersSplit = authorizationSignedHeaders.Split(";");
            Dictionary<string, string> requestHeadersSign = new Dictionary<string, string>();
            for (int j = 0; j < signedHeadersSplit.Count(); j++)
            {
                string value;

                if (requestHeaders.TryGetValue(signedHeadersSplit[j], out value))
                {
                    requestHeadersSign.Add(signedHeadersSplit[j], value);
                }
            }
            string hexDataString = SignerBase.EMPTY_BODY_SHA256;
            Uri uri = new Uri(request.GetDisplayUrl().ToString());
            string pathResource = GetPathResources(uri.AbsolutePath);

            if (request.Method.ToUpper() == "POST" || request.Method.ToUpper() == "PUT")
            {
                string bodyContent = new StreamReader(request.Body).ReadToEnd();
                request.Body.Position = 0;
                Debug.WriteLine("BODY_CONTENT: " + bodyContent);
                if (!string.IsNullOrEmpty(bodyContent))
                {
                    var postDataStringBytes = _canonicalRequestHashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(bodyContent));
                    hexDataString = ToHexString(postDataStringBytes, true);
                }
            }
            Debug.WriteLine("BODY_CONTENT_HASH: " + hexDataString);
            var querystring = request.QueryString.ToString().Replace("?", "");
            var authorizationModel = signer.ComputeSignature(requestHeadersSign, pathResource, querystring, hexDataString, tpaDateHeaderAsDateTimeOffset.UtcDateTime, headerCLientIdSplit, clientSecretkey);

            if (authorizationModel == null)
                return new HmacValidationResult(HmacValidationResultCode.AuthorizationInvalid, "Authorization is invalid.");

            if (string.Compare(authorizationModel.Signature, authorizationSignature) != 0)
                return new HmacValidationResult(HmacValidationResultCode.AuthorizationInvalid, "Authorization is invalid.");

            return new HmacValidationResult(HmacValidationResultCode.Ok, "Authorization is valid.");
        }
    }

    public class HttpRequestBase { }
}