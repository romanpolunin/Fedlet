using System.Collections.Generic;
using Sun.Identity.Saml2;

namespace Sun.Identity.Common
{
	/// <summary>Defines a repository for retrieving configuration information</summary>
	public interface IFedletRepository
	{
		/// <summary>Get all configuration information for all circles of trust.</summary>
		Dictionary<string, CircleOfTrust> GetCircleOfTrusts();

		/// <summary>Get all configuration information for the service provider.</summary>
		IServiceProvider GetServiceProvider();

		/// <summary>Get all configuration information for all identity providers.</summary>
		Dictionary<string, IdentityProvider> GetIdentityProviders();
	}
}