using Newtonsoft.Json;
using System;
using System.Web;
using System.Web.Mvc;

namespace SingleSignOnAuth
{
    public class SSOAuthenticate :  AuthorizeAttribute
	{ 
        protected override bool AuthorizeCore(HttpContextBase httpContext)
        {	
			return Authenticator.Instance.IsAuthenticated(httpContext);
		}  
	}

	public class SSOInformation
	{
		[JsonProperty("access_token")]
		public string AccessToken { get; set; }

		[JsonProperty("token_type")]
		public string TokenType { get; set; }

		[JsonProperty("expires_in")]
		public int ExpiresIn { get; set; }

		[JsonProperty("refresh_token")]
		public string RefreshToken { get; set; }
	}

	public class ErrorInformation
	{
		[JsonProperty("error")]
		public string Error { get; set; }
		[JsonProperty("error_description")]
		public string Error_Description { get; set; }
		[JsonProperty("Trace ID")]
		public string TraceID { get; set; }
		[JsonProperty("Correlation ID")]
		public string CorrelationID { get; set; }
		[JsonProperty("Timestamp")]
		public DateTime TimeStamp { get; set; }
	}
}
