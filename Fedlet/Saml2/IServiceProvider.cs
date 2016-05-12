using System;
using System.Collections;

namespace Sun.Identity.Saml2
{
	/// <summary>
	/// Represents all metadata for a Service Provider.
	/// </summary>
	public interface IServiceProvider
	{
        /// <summary>
        /// Gets a TimeSpan value to help tolerate NotOnOrAfter and NotBefore constraints checks
        /// due to SP-IdP time difference. 
        /// </summary>
        TimeSpan AssertionTimeSkew { get; }

        /// <summary>
		/// Gets a value indicating whether the standard metadata value for 
		/// AuthnRequestsSigned is true or false.
		/// </summary>
		bool AuthnRequestsSigned { get; }

		/// <summary>
		/// Gets the entity ID for this service provider.
		/// </summary>
		string EntityId { get; }

		/// <summary>
		/// Gets the meta alias for this service provider.
		/// </summary>
		string MetaAlias { get; }

		/// <summary>
		/// Gets the certificate alias, installed on this service provider, 
		/// for encryption.
		/// </summary>
		string EncryptionCertificateAlias { get; }

		/// <summary>
		/// Gets a list of relay state URLs that are considered acceptable
		/// as a parameter in the various SAMLv2 profiles.
		/// </summary>
		ArrayList RelayStateUrlList { get; }

		/// <summary>
		/// Gets the certificate alias, installed on this service provider, 
		/// for signing.
		/// </summary>
		string SigningCertificateAlias { get; }

        /// <summary>
        /// Gets the identifier of the signature method.
        /// </summary>
        string SignatureMethod { get; }

        /// <summary>
        /// Gets the identifier of the digest method.
        /// </summary>
        string DigestMethod { get; }

        /// <summary>
        /// Gets a value indicating whether the extended metadata value for 
        /// wantArtifactResponseSigned is true or false.
        /// </summary>
        bool WantArtifactResponseSigned { get; }

		/// <summary>
		/// Gets a value indicating whether the standard metadata value for 
		/// WantAssertionsSigned is true or false.
		/// </summary>
		bool WantAssertionsSigned { get; }

		/// <summary>
		/// Gets a value indicating whether the extended metadata value for 
		/// wantPOSTResponseSigned is true or false.
		/// </summary>
		bool WantPostResponseSigned { get; }

		/// <summary>
		/// Gets a value indicating whether the extended metadata value for 
		/// wantLogoutRequestSigned is true or false.
		/// </summary>
		bool WantLogoutRequestSigned { get; }

		/// <summary>
		/// Gets a value indicating whether the extended metadata value for 
		/// wantLogoutResponseSigned is true or false.
		/// </summary>
		bool WantLogoutResponseSigned { get; }

		/// <summary>
		/// Obtain the assertion consumer service location based on the given binding.
		/// </summary>
		/// <param name="binding">The binding associated with the desired consumer service.</param>
		/// <returns>Service location as defined in the metadata for the binding, null if not found.</returns>
		string GetAssertionConsumerServiceLocation(string binding);

		/// <summary>
		/// Obtain the assertion consumer service location based on the given binding.
		/// </summary>
		/// <param name="binding">The binding associated with the desired consumer service.</param>
		/// <param name="index">The index associated with the desired consumer service.</param>
		/// <returns>Service location as defined in the metadata for the binding, null if not found.</returns>
		string GetAssertionConsumerServiceLocation(string binding, string index);

		/// <summary>
		/// <para>
		/// Obtain the AuthLevel for the given uri reference found in the
		/// service provider extended metadata. An example would like as
		/// follows:
		/// </para>
		/// <para>
		///  &lt;Attribute name="spAuthncontextClassrefMapping"&gt;
		///    &lt;Value&gt;urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport|0|default&lt;/Value&gt;
		///  &lt;/Attribute&gt;
		/// </para>
		/// </summary>
		/// <param name="classReference">
		/// AuthnContextClassRef mapped to the desired Auth Level
		/// </param>
		/// <returns>Mapped integer for the given class reference.</returns>
		int GetAuthLevelFromAuthnContextClassRef(string classReference);

		/// <summary>
		/// <para>
		/// Obtain the AuthLevel for the given uri reference found in the
		/// service provider extended metadata. An example would like as
		/// follows:
		/// </para>
		/// <para>
		///  &lt;Attribute name="spAuthncontextClassrefMapping"&gt;
		///    &lt;Value&gt;urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport|0|default&lt;/Value&gt;
		///  &lt;/Attribute&gt;
		/// </para>
		/// </summary>
		/// <param name="authLevel">
		/// AuthLevel mapped to the desired AuthnContextClassRef
		/// </param>
		/// <returns>Class reference found for the specified AuthLevel</returns>
		string GetAuthnContextClassRefFromAuthLevel(int authLevel);

		/// <summary>
		/// Returns a string representing the configured metadata for
		/// this service provider.  This will include key information
		/// as well if the metadata and extended metadata have this
		/// information specified.
		/// </summary>
		/// <param name="signMetadata">
		/// Flag to specify if the exportable metadata should be signed.
		/// </param>
		/// <returns>
		/// String with runtime representation of the metadata for this
		/// service provider.
		/// </returns>
		string GetExportableMetadata(bool signMetadata);
	}
}