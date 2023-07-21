using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Cloud_Net_Sdk_Hmac_Lib.Models;
using Newtonsoft.Json;

namespace Cloud_Net_Sdk_Hmac_Lib.Signers
{
    public class RestApiHmac<T>
    {
        private const string TIMEZONE = "SE Asia Standard Time";
        private string _accessToken = "";
        public const string DATETIME_FORMAT = "dd/MM/yyyy";
        private ResponFormatOption _responseFormatOption = ResponFormatOption.ApiJsonResultData;
        private RequestDataFormatOption _requestDataFormatOption = RequestDataFormatOption.JsonFormat;
        private static HashAlgorithm _canonicalRequestHashAlgorithm = HashAlgorithm.Create("SHA-256");

        private static string ISO8601BasicFormat = "yyyy-MM-ddTHH\\:mm\\:sszz00";

        public RestApiHmac() : this("") { }

        public RestApiHmac(string accessToken)
        {
            _accessToken = accessToken;
        }

        public void SetResponFormat(ResponFormatOption responseFormatOption)
        {
            _responseFormatOption = responseFormatOption;
        }

        public void SetRequestDataFormat(RequestDataFormatOption requestDataFormatOption)
        {
            _requestDataFormatOption = requestDataFormatOption;
        }

        //Call http request to endpoint url
        public ApiJsonResultData<T> DoRequestV1(HttpMethod methodOption, string url, string clientId, string secretId, object postData = null,
            Dictionary<string, string> headerValues = null)
        {
            var response = DoRequestProcessing(methodOption, url, clientId, secretId, postData, headerValues);
            return response.OldResponse;
        }
        public ApiResponse<T> DoRequestV2(HttpMethod methodOption, string url, string clientId, string secretId, object postData = null,
            Dictionary<string, string> headerValues = null)
        {
            var response = DoRequestProcessing(methodOption, url, clientId, secretId, postData, headerValues);
            return response.NewResponse;
        }

        public ModelResponse<T> DoRequestProcessing(HttpMethod methodOption, string url, string clientId, string secretId, object postData = null,
            Dictionary<string, string> headerValues = null)
        {
            try
            {
                ModelResponse<T> mRet = new ModelResponse<T>();
                var jsonConvert = JsonConvert.SerializeObject(postData).ToString();
                string dataAsJson = jsonConvert == "null" ? null : jsonConvert;
                string hexDataString = SignerBase.EMPTY_BODY_SHA256;
                //do not use this line in production
                ServicePointManager.ServerCertificateValidationCallback = delegate(object s, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors) { return true; };
                var response = new HttpWebResponse();
                Uri uri = new Uri(url);
                CultureInfo.CurrentCulture.ClearCachedData();
                var requestDateTime = DateTime.UtcNow;
                Debug.WriteLine("RequestDateTime: " + requestDateTime);
                headerValues = InitHeaderForSigning(uri, headerValues, requestDateTime);
                var signer = new SignerForAuthorizationHeader
                {
                    EndpointUri = uri,
                    HttpMethod = methodOption.ToString().ToUpper() //
                };
                string pathResource = GetPathResources(uri.AbsolutePath);
                // check medthod POST and GET 
                if (methodOption == HttpMethod.POST || methodOption == HttpMethod.PUT)
                {
                    // check  body data null
                    if (postData == null)
                    {
                        mRet.NewResponse = new ApiResponse<T>(HttpStatusCode.InternalServerError, "BODY_EMPTY");
                        mRet.OldResponse = new ApiJsonResultData<T>(false, "BODY_EMPTY");
                        return mRet;
                    }
                    Debug.WriteLine("Body_Before_Hash: " + postData);
                    byte[] hashBody = _canonicalRequestHashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(dataAsJson));
                    hexDataString = ToHexString(hashBody, true);
                    Debug.WriteLine("Body_Hex: " + hexDataString);
                }
                string queryString = uri.Query;
                //check query string is null or empty
                if (!string.IsNullOrEmpty(queryString)) queryString = queryString.Replace("?", "");
                var authorization = signer.ComputeSignature(headerValues, pathResource, queryString, hexDataString, requestDateTime, clientId, secretId);
                headerValues.Add("X-Authorization", authorization.Authorization);

                response = CallHttpAction(methodOption, url, headerValues, dataAsJson);
                return ReadResponse(response);
            }
            catch (WebException ex)
            {
                using(WebResponse response = ex.Response)
                {
                    HttpWebResponse httpResponse = (HttpWebResponse) response;
                    if (httpResponse == null) return ReadResponse(httpResponse, ex.Message);
                    return ReadResponse(httpResponse);
                }
            }
        }
        private HttpWebResponse CallHttpAction(HttpMethod httpMethod, string url, Dictionary<string, string> headerValues = null, string postData = null)
        {
            var request = WebRequest.Create(url);
            request.Method = httpMethod.ToString();
            //request.ContentType = "application/json";
            //check header value
            if (headerValues != null)
            {
                foreach (var header in headerValues.Keys)
                {
                    request.Headers.Add(header, headerValues[header]);
                }
            }
            //check body data
            if (postData != null)
            {
                using(var streamWriter = new StreamWriter(request.GetRequestStream()))
                {
                    streamWriter.Write(postData);
                    streamWriter.Flush();
                    return (HttpWebResponse) request.GetResponse();
                }
            }
            return (HttpWebResponse) request.GetResponse();
        }

        private ModelResponse<T> ReadResponse(HttpWebResponse response, string message = null)
        {
            ModelResponse<T> mRet = new ModelResponse<T>();
            string responseBody = string.Empty;
            //check respoonse of http
            if (response == null)
            {
                ApiResponse<T> errorResponse = new ApiResponse<T>(HttpStatusCode.InternalServerError, message);
                errorResponse.Message = message;
                mRet.NewResponse = errorResponse;
                mRet.OldResponse = new ApiJsonResultData<T>(false, message);
                return mRet;
            }
            using(var responseStream = response.GetResponseStream())
            {
                //check null of stream
                if (responseStream != null)
                {
                    using(var reader = new StreamReader(responseStream))
                    {
                        responseBody = reader.ReadToEnd();
                    }
                }
            }
            if (responseBody.Contains("503 Service Unavailable"))
            {
                mRet.NewResponse = new ApiResponse<T>(HttpStatusCode.ServiceUnavailable, message);
                mRet.OldResponse = new ApiJsonResultData<T>(false, message);
                return mRet;
            }
            if (response.StatusCode != HttpStatusCode.OK)
            {
                mRet.NewResponse = new ApiResponse<T>(response.StatusCode, message??response.StatusDescription);
                mRet.OldResponse = new ApiJsonResultData<T>(false, message??response.StatusDescription);
                return mRet;
            }
            try
            {
                mRet.NewResponse = JsonConvert.DeserializeObject<ApiResponse<T>>(responseBody);
                mRet.OldResponse = JsonConvert.DeserializeObject<ApiJsonResultData<T>>(responseBody);
                return mRet;
            }
            catch 
            {
                mRet.NewResponse = new ApiResponse<T>(HttpStatusCode.InternalServerError,responseBody);
                mRet.OldResponse = new ApiJsonResultData<T>(false, responseBody);
                return mRet;
            }
           
        }

        private Dictionary<string, string> InitHeaderForSigning(Uri uri, Dictionary<string, string> headers, DateTime utcDate)
        {
            //check headers values
            if (headers == null)
                headers = new Dictionary<string, string>();

            if (!headers.ContainsKey("host"))
            {
                headers.Add("host", uri.Host);
            }

            if (!headers.ContainsKey("x-tpa-date"))
            {
                headers.Add("x-tpa-date", utcDate.ToString(ISO8601BasicFormat, CultureInfo.InvariantCulture));
            }

            if (!headers.ContainsKey("content-type"))
            {
                headers.Add("content-type", "application/json");
            }
            return headers;
        }

        private string GetPathResources(string path)
        {
            // remove first character / 
            if (path != null)
                path = path.Substring(1);
            Regex rgxVersion = new Regex("[v][\\d]");
            string[] pathSplit = path.Split("/");
            string pathResource = "";
            int postVersion = -1;
            for (var i = 0; i < pathSplit.Count(); i++)
            {
                //get the positoin of version v1, v2, v3 
                if (rgxVersion.IsMatch(pathSplit[i]))
                {
                    postVersion = i;
                }
            }
            //remove item version v
            if (postVersion != -1)
            {
                pathSplit = pathSplit.Where(x => x != pathSplit[postVersion]).ToArray();
            }
            pathResource = pathSplit[0];
            // check if section > 2
            if (pathSplit.Count() > 2)
            {
                pathResource = pathSplit[1];
            }
            return pathResource;
        }

        private string ToHexString(byte[] data, bool lowercase)
        {
            var sb = new StringBuilder();
            for (var i = 0; i < data.Length; i++)
            {
                sb.Append(data[i].ToString(lowercase ? "x2" : "X2"));
            }
            return sb.ToString();
        }
    }

}