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
 

to get all claims and related authenticated user information, you can wire this code :
var principal = HttpContext.User as SSOPrincipal;
if (principal != null)
{
  //principal.Claims : will have all claims which you can convert according to your need.
  //principal.Identity : will give all information regarding the identity like name,email,upn and everything.
    principal.
}
