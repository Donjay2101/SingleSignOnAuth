this library is created to implement SSO on App.net MVC which supports .net framework 4.0

to use this library you will need to add below settings in appsettings

  <appSettings>
    <add key="SSO.LoginURI" value="" />
    <add key="SSO.TokenURI" value="" />
    <add key="SSO.ClientID" value="" />
    <add key="SSO.ClientSecret" value="" />
    <add key="SSO.TenantID" value="" />
    <add key="SSO.Scope" value="" />
    <add key="SSO.RedirectURI" value="" />
  </appSettings>




after adding above settings need to add attribute to controller which needs to be authorized.

[SSOAuthenicate]
 public class HomeController : Controller
 {
 }
 
 