using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace Sun.Identity.Saml2
{
	/// <summary>
	/// Represents all metadata for an Identity Provider.
	/// </summary>
	public interface IIdentityProvider
	{
		/// <summary>
		/// Gets the entity ID of this identity provider.
		/// </summary>
		string EntityId { get; }

		/// <summary>
		/// Gets the encoded X509 certifcate located within the identity
		/// provider's metadata.
		/// </summary>
		string EncodedSigningCertificate { get; }

		/// <summary>
		/// Gets the X509 signing certificate for this identity provider.
		/// </summary>
		X509Certificate2 SigningCertificate { get; }

		/// <summary>
		/// Gets the list of single log out service locations, if present,
		/// otherwise an empty list.
		/// </summary>
		XmlNodeList SingleLogOutServiceLocations { get; }

		/// <summary>
		/// Gets the list of single sign on service locations, if present,
		/// otherwise an empty list.
		/// </summary>
		XmlNodeList SingleSignOnServiceLocations { get; }

		/// <summary>
		/// Gets a value indicating whether the extended metadata for
		/// WantArtifactResolveSigned is true or false.
		/// </summary>
		bool WantArtifactResolveSigned { get; }

		/// <summary>
		/// Gets a value indicating whether the metadata value for 
		/// WantAuthnRequestsSigned is true or false.
		/// </summary>
		bool WantAuthnRequestsSigned { get; }

		/// <summary>
		/// Gets a value indicating whether the metadata value for
		/// WantLogoutRequestSigned is true or false.
		/// </summary>
		/// <returns></returns>
		bool WantLogoutRequestSigned { get; }

		/// <summary>
		/// Gets a value indicating whether the metadata value for
		/// WantLogoutResponseSigned is true or false.
		/// </summary>
		bool WantLogoutResponseSigned { get; }

		/// <summary>
		/// Obtain the artifact resolution service location based on the given binding.
		/// </summary>
		/// <param name="binding">The binding associated with the desired service.</param>
		/// <returns>Service location as defined in the metadata for the binding, null if not found.</returns>
		string GetArtifactResolutionServiceLocation(string binding);

		/// <summary>
		/// Obtain the single logout location based on the given binding.
		/// </summary>
		/// <param name="binding">
		/// The binding (should be made into constants / types).
		/// </param>
		/// <returns>
		/// Service location as defined in the metadata for the specified IDP
		/// and binding.
		/// </returns>
		string GetSingleLogoutServiceLocation(string binding);

		/// <summary>
		/// Obtain the single logout resopnse location based on the given
		/// binding.
		/// </summary>
		/// <param name="binding">
		/// The binding (should be made into constants / types).
		/// </param>
		/// <returns>
		/// Service response location as defined in the metadata for the
		/// specified IDP and binding.
		/// </returns>
		string GetSingleLogoutServiceResponseLocation(string binding);

		/// <summary>
		/// Obtain the single sign on location based on the given binding.
		/// </summary>
		/// <param name="binding">The binding (should be made into constants / types).</param>
		/// <returns>Service location as defined in the metadata for the specified IDP and binding.</returns>
		string GetSingleSignOnServiceLocation(string binding);
	}
}