using System;
using System.Net;

public class TokenDataVerifyResponse
{
    public string Identity_uuid { get; set; }
    public string Scope { get; set; }
    public string Expires_in { get; set; }
}