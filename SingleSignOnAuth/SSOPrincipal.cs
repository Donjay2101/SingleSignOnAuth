using System;
using System.Collections;
using System.Collections.Generic;
using System.Security.Principal;

namespace SingleSignOnAuth
{
    /// <summary>
    /// Represents a SSO Principal
    /// </summary>
    [Serializable]
	public class SSOPrincipal : IPrincipal
	{
		# region private variables
		
		private readonly IIdentity _identity;
		private readonly ArrayList _roles;
		private readonly Dictionary<string, object> _claims;
		

		#endregion

		# region Constructor
		/// <summary>
		/// Initializes a new instance of the GenericPrincipal class 
		/// from a SSOIdentity and an ArrayList of role names 
		/// to which the user represented by that SSOIdentity belongs
		/// </summary>
		/// <param name="id"></param>
		/// <param name="rolesArray"></param>
		public SSOPrincipal(IIdentity id, ArrayList rolesArray,Dictionary<string,object> claims)
		{
			_identity = id;
			_roles = rolesArray;
			_claims = claims;


		}
		#endregion

		# region Methods
		/// <summary>
		/// Determines whether the current SSOPrincipal belongs to the specified role.
		/// </summary>
		/// <param name="role">The name of the role for which to check membership</param>
		/// <returns>true if the current SSOPrincipal is a member of the specified role; 
		/// otherwise, false.</returns>
		public bool IsInRole(string role)
		{
			return _roles.Contains( role );
		}

		#endregion

		# region Properties
		/// <summary>
		/// Gets the SSOIdentity of the user represented by the current SSOPrincipal.
		/// </summary>
		public IIdentity Identity
		{
			get { return _identity; }
			
		}

		public Dictionary<string,object> Claims
		{
			get { return _claims; }

		}
		#endregion
	}
}
