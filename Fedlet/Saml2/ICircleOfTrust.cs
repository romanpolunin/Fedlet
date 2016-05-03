using System;

namespace Sun.Identity.Saml2
{
	public interface ICircleOfTrust
	{
		/// <summary>
		/// Gets the name of the circle of trust
		/// </summary>
		string Name { get; }

		/// <summary>
		/// Gets the saml2 reader service url, empty string if not specified,
		/// null attribute is not found.
		/// </summary>
		Uri ReaderServiceUrl { get; }

		/// <summary>
		/// Gets the saml2 writer service url, empty string if not specified,
		/// null attribute is not found.
		/// </summary>
		Uri WriterServiceUrl { get; }

		/// <summary>
		/// Checks service provider and identity provider Entity ID's to
		/// ensure they are found in the Trusted Providers property.
		/// </summary>
		/// <param name="serviceProviderEntityId">Service Provider EntityID</param>
		/// <param name="identityProviderEntityId">Identity Provider EntityID</param>
		/// <returns>True if providers are trusted, false otherwise.</returns>
		bool AreProvidersTrusted(string serviceProviderEntityId, string identityProviderEntityId);
	}
}