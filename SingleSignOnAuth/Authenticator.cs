using JWT.Builder;
using Newtonsoft.Json;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Web;

namespace SingleSignOnAuth
{
    public sealed class Authenticator
    {
        private static object _lock = new object();
		const string LOGINURL_KEY = "SSO.LoginURI";
		const string CLIENTID_KEY = "SSO.ClientID";
		const string CLIENT_SECRET_KEY = "SSO.ClientSecret";
		const string TENANTID_KEY = "SSO.TenantID";
		const string SCOPE_KEY = "SSO.Scope";
		const string REDIRECT_URI_KEY = "SSO.RedirectURI";
		const string TOKEN_URI_KEY = "SSO.TokenURI";
		private static Authenticator _instance;


        public static Authenticator Instance
        {
            get
            {
                lock (_lock)
                {
                    if (_instance == null)
                    {
                        _instance = new Authenticator();
                    }
                    return _instance;
                }
            }
        }


        public bool IsAuthenticated(HttpContextBase httpContext)
        {
			bool isAuthenticated = false;
			string loginUrl = ConfigurationManager.AppSettings[LOGINURL_KEY];
			string clientID = ConfigurationManager.AppSettings[CLIENTID_KEY];
			string scopes = ConfigurationManager.AppSettings[SCOPE_KEY];
			string clientSecret = ConfigurationManager.AppSettings[CLIENT_SECRET_KEY];
			string redirectUri = ConfigurationManager.AppSettings[REDIRECT_URI_KEY];
			string tokenUri = ConfigurationManager.AppSettings[TOKEN_URI_KEY];


			var request = httpContext.Request;
			var response = httpContext.Response;

			string cookieName = ".SSO_AUTH"; //ConfigurationManager.AppSettings[AUTHENTICATION_COOKIE_KEY];
			if (cookieName == null || cookieName.Trim() == String.Empty)
			{
				throw new Exception(" SSOAuthentication.Cookie.Name entry not found in appSettings section section of Web.config");
			}

			if (request.Cookies.Count > 0 && request.Cookies[".ASPXAUTH"] != null && request.Cookies[cookieName.ToUpper()] != null)
			{
				HttpCookie authCookie = request.Cookies[".ASPXAUTH"];
				if (authCookie != null)
				{
					HttpCookie cookie = request.Cookies[cookieName.ToUpper()];
					if (cookie != null)
					{
						string str = cookie.Value;
						SSOIdentity userIdentity = SSOAuthentication.Decrypt(str);
						string[] roles = userIdentity.UserRoles.Split(new char[] { '|' });
						var claims = userIdentity.Claims;
						ArrayList arrRoles = new ArrayList();
						arrRoles.InsertRange(0, roles);
						SSOPrincipal principal = new SSOPrincipal(userIdentity, arrRoles, claims);
						httpContext.User = principal;
						Thread.CurrentPrincipal = principal;
						return userIdentity.IsAuthenticated;
					}
				}
			}


			if (loginUrl == null || loginUrl.Trim() == String.Empty)
			{
				throw new Exception(" SSOAuthentication.LoginUrl entry not found in appSettings section of Web.config");
			}


			loginUrl += $"?client_id={clientID}&response_type=code&scope={scopes}";

			if (!isAuthenticated && request.QueryString.HasKeys() && request.QueryString.GetValues("code").Length > 0)
			{
				string code = request.QueryString.GetValues("code")[0];

				WebClient wc = new WebClient();
				var reqparm = new NameValueCollection();
				reqparm.Add("client_id", clientID);
				reqparm.Add("scope", scopes);
				reqparm.Add("code", code);
				reqparm.Add("redirect_uri", redirectUri);
				reqparm.Add("grant_type", "authorization_code");
				reqparm.Add("client_secret", clientSecret);
				string reirUrl = tokenUri;
				HttpWebResponse httpResponse = null;
				string serviceResponse = WebServiceRedirect(request, "application/x-www-form-urlencoded", "POST", reirUrl, reqparm, out httpResponse);
				ErrorInformation errors = JsonConvert.DeserializeObject<ErrorInformation>(serviceResponse);
				if (errors != null && !string.IsNullOrEmpty(errors.Error) && errors.Error != null)
				{
					throw new Exception(JsonConvert.SerializeObject(errors));
				}

				SSOInformation tokeninfo = JsonConvert.DeserializeObject<SSOInformation>(serviceResponse);
				if (tokeninfo != null)
				{
					var token = DecodeJWT(tokeninfo.AccessToken);
					if (token != null)
					{
						object userID, upk, email;
						token.TryGetValue("upn", out userID);
						token.TryGetValue("unique_name", out upk);
						token.TryGetValue("email", out email);
						SSOIdentity userIdentity = new SSOIdentity((string)userID, 0, true, false, (string)upk, (string)email, "", token);
						SSOPrincipal principal = new SSOPrincipal(userIdentity, null, token);
						httpContext.User = principal;
						Thread.CurrentPrincipal = principal;


						isAuthenticated = SSOAuthentication.RedirectFromLoginPage(userIdentity, redirectUri, tokeninfo.ExpiresIn);
					}
					else
					{
						isAuthenticated = false;
					}
				}

			}

			if (!isAuthenticated)
			{
				response.RedirectPermanent(loginUrl);
			}

			return isAuthenticated;
		}

		/// <summary>
		/// Returns an instance decrypted token values, 
		/// given an encrypted token  obtained from SSO.
		/// </summary>
		/// <param name="token">access token to decrypty</param>
		/// <returns>SSOIdentity object</returns>
		Dictionary<string, object> DecodeJWT(string token)
		{
			try
			{
				var json = JwtBuilder.Create().Decode<Dictionary<string, object>>(token);
				return json;
			}
			catch
			{
				throw;
			}

		}


		string WebServiceRedirect(HttpRequestBase request, string contentType, string method, string url, NameValueCollection nameValueCollection, out HttpWebResponse newResponse)
		{
			byte[] bytes = request.BinaryRead(request.TotalBytes);
			char[] responseBody = Encoding.UTF8.GetChars(bytes, 0, bytes.Length);

			HttpWebRequest newRequest = (HttpWebRequest)WebRequest.Create(url);
			newRequest.AllowAutoRedirect = false;
			newRequest.ContentType = contentType;// "application/x-www-form-urlencoded";
			newRequest.UseDefaultCredentials = true;
			newRequest.UserAgent = ".NET Web Proxy";
			newRequest.Referer = url;
			newRequest.Method = method;// "POST";

			StringBuilder parameters = new StringBuilder();

			foreach (string key in nameValueCollection.Keys)
			{
				parameters.AppendFormat("{0}={1}&",
					HttpUtility.UrlEncode(key),
					HttpUtility.UrlEncode(nameValueCollection[key]));
			}

			if (newRequest.Method.ToLower() == "post")
			{
				using (StreamWriter writer = new StreamWriter(newRequest.GetRequestStream()))
				{
					writer.Write(parameters.ToString());
				}
			}
			if (request.AcceptTypes.Length > 0)
				newRequest.MediaType = request.AcceptTypes[0];

			foreach (string str in request.Headers.Keys)
			{
				try { newRequest.Headers.Add(str, request.Headers[str]); }
				catch { }
			}
			string temp = "";
			try
			{
				newResponse = (HttpWebResponse)newRequest.GetResponse();
				using (System.IO.StreamReader sw = new System.IO.StreamReader((newResponse.GetResponseStream())))
				{
					temp = sw.ReadToEnd();
					sw.Close();
				}
			}
			catch (WebException exc)
			{
				using (System.IO.StreamReader sw = new System.IO.StreamReader((exc.Response.GetResponseStream())))
				{
					newResponse = (HttpWebResponse)exc.Response;
					temp = sw.ReadToEnd();
					sw.Close();
				}
			}

			return temp;
		}
	}
}
