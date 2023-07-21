using System;
using System.Net;
using System.Xml;

namespace Cloud_Net_Sdk_Hmac_Lib.Models
{
    public class ApiJsonResultData
    {
        /// <summary>
        /// 
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public object Data { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public ApiJsonResultData()
        {

        }

        /// <summary>
        /// Return with object respone
        /// </summary>
        /// <param name="success"></param>
        /// <param name="objectRespone"></param>
        public ApiJsonResultData(bool success, object objectRespone)
        {
            Success = success;
            Data = objectRespone;
        }
    }

    public class ApiJsonResultData<T>
    {
        public bool Success { get; set; }

        public T Data { get; set; }

        public string ErrorMessage { get; set; }

        public ApiJsonResultData(bool success, string data)
        {
            Success = success;
            Data = GetValue<T>(data);
        }
        public ApiJsonResultData() { }
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
}