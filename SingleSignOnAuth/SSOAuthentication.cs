using Newtonsoft.Json;
using System;
using System.Collections;
using System.Reflection;
using System.Text;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace SingleSignOnAuth
{
    public sealed class SSOAuthentication
	{
	

		#region static methods
		/// <summary>
		/// Produces a string containing an encrypted string for an authenticated User Identity
		/// suitable for use in an HTTP cookie given a SSOIdentity
		/// </summary>
		/// <param name="identity">SSOIdentity class for the authenticated user</param>
		/// <returns>Encrypted string</returns>
		public static string Encrypt(SSOIdentity identity)
		{
			string encryptedString = String.Empty;
			try
			{
				var str = JsonConvert.SerializeObject(identity);
				encryptedString = SSOEncryption.Encrypt(str);
			}
			catch (Exception e)
			{
				string str = e.Message;
				throw;
			}
			return encryptedString;
		}

		/// <summary>
		/// Returns an instance of a SSOIdentity class, 
		/// given an encrypted authentication string obtained from an HTTP cookie.
		/// </summary>
		/// <param name="encryptedInput">Encrypted string conataining User Identity</param>
		/// <returns>SSOIdentity object</returns>
		public static SSOIdentity Decrypt(string encryptedInput)
		{
			SSOIdentity identity = null;
			try
			{
				string decryptedString = SSOEncryption.Decrypt(encryptedInput);
				identity = JsonConvert.DeserializeObject<SSOIdentity>(decryptedString);
			}
			catch (Exception e)
			{
				string str = e.Message;
				throw;
			}
			return identity;
		}

		/// <summary>
		/// Redirects an authenticated user back to the originally requested URL.
		/// </summary>
		/// <param name="identity">SSOIdentity of an authenticated user</param>
		public static bool RedirectFromLoginPage(SSOIdentity identity, string redirectUri, int tokenExpirationTime = 3600)
		{
			string cookieName = ".SSO_AUTH";// ConfigurationManager.AppSettings[AUTHENTICATION_COOKIE_KEY];
			if (cookieName == null || cookieName.Trim() == String.Empty)
			{
				throw new Exception("There are some issues in setting SSO at the moment. please contact maintainence.");
			}
			FormsAuthentication.SetAuthCookie(identity.UserName, false);


			HttpRequest request = HttpContext.Current.Request;
			HttpResponse response = HttpContext.Current.Response;


			string encryptedUserDetails = Encrypt(identity);

			HttpCookie userCookie = new HttpCookie(cookieName.ToUpper(), encryptedUserDetails);
			userCookie.Expires = DateTime.Now.AddSeconds(tokenExpirationTime);
			response.Cookies.Add(userCookie);
			return true;
        }

		#endregion

		#region private methods
		private object GetConvertedValue(string propertyValue, string propertyType)
		{
			Type argType = Type.GetType(propertyType);
			Object obj = new Object();
			if (argType == Type.GetType("System.String"))
			{
				obj = propertyValue.Trim();  // returning Primitive object
			}
			else
			{
				obj = Activator.CreateInstance(argType);  // creating an object of ArgumentType 
				obj = argType.InvokeMember("Parse", BindingFlags.Default | BindingFlags.InvokeMethod, null, obj, new object[] { propertyValue.Trim() });
			}

			return obj;
		}

		/// <summary>
		/// Used to split a string into an string array based on a separator
		/// </summary>
		/// <param name="seperator"></param>
		/// <param name="str"></param>
		/// <param name="strArray"></param>
		private static void Split(string seperator, string str, ArrayList strArray)
		{
			try
			{
				int start = 0, end = 0;
				end = str.IndexOf(seperator);
				if (end <= -1)
				{
					end = str.Length;
					strArray.Add(str.Substring(start, end - start));
					return;
				}
				strArray.Add(str.Substring(start, end - start));

				start = end + seperator.Length;
				end = str.Length;

				Split(seperator, str.Substring(start, end - start), strArray);
			}
			catch (Exception ex)
			{
				throw (ex);
			}
		}

		#endregion

		#region Properties
		/// <summary>
		/// Returns the configured cookie name used for the current application
		/// </summary>
		public string CookieName
		{
			get
			{
				string cookieName = ".SSO_AUTH";// ConfigurationManager.AppSettings[AUTHENTICATION_COOKIE_KEY];
				if (cookieName == null || cookieName.Trim() == String.Empty)
				{
					throw new Exception("There are some issues in setting SSO at the moment. please contact maintainence.");
				}
				return cookieName;
			}
		}
		#endregion
	}
}
