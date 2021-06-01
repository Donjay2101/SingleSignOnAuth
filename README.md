
this library is created to implement SSO on App.net MVC which supports .net framework 4.0
# step 1: change web.config file
to use this library you will need to add below settings in appsettings
```c#
  <appSettings>
    <add key="SSO.LoginURI" value="" />
    <add key="SSO.TokenURI" value="" />
    <add key="SSO.ClientID" value="" />
    <add key="SSO.ClientSecret" value="" />
    <add key="SSO.TenantID" value="" />
    <add key="SSO.Scope" value="" />
    <add key="SSO.RedirectURI" value="" />
  </appSettings>

```



# step 2: Add attribute to proctected resource.
after adding above settings need to add attribute to controller which needs to be authorized.
```c#
[SSOAuthenicate]
 public class HomeController : Controller
 {
 
 }
```

 
# step 3:  reterive information of authenticated user.  
to get all claims and related authenticated user information, you can wire this code :
```c#
var principal = HttpContext.User as SSOPrincipal;
if (principal != null)
{
  //principal.Claims : will have all claims which you can convert according to your need.
  //principal.Identity : will give all information regarding the identity like name,email,upn and everything.
    principal.
}
```

