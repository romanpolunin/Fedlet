/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 * 
 * Copyright (c) 2009-2010 Sun Microsystems Inc. All Rights Reserved
 * 
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 * 
 * You can obtain a copy of the License at
 * https://opensso.dev.java.net/public/CDDLv1.0.html or
 * opensso/legal/CDDLv1.0.txt
 * See the License for the specific language governing
 * permission and limitations under the License.
 * 
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at opensso/legal/CDDLv1.0.txt.
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 * 
 * $Id: IdentityProvider.cs,v 1.6 2010/01/19 18:23:09 ggennaro Exp $
 */

using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Sun.Identity.Properties;
using Sun.Identity.Saml2.Exceptions;

namespace Sun.Identity.Saml2
{
	/// <summary>
	/// Class representing all metadata for an Identity Provider.
	/// </summary>
	public class IdentityProvider : IIdentityProvider
	{
	    #region Members

	    private readonly Saml2Utils _saml2Utils;

		/// <summary>
		/// XML document representing the extended metadata for this Identity 
		/// Provider.
		/// </summary>
		private readonly XmlDocument _extendedMetadata;

		/// <summary>
		/// Namespace Manager for the extended metadata.
		/// </summary>
		private readonly XmlNamespaceManager _extendedMetadataNsMgr;

		/// <summary>
		/// XML document representing the metadata for this Identity Provider.
		/// </summary>
		private readonly XmlDocument _metadata;

		/// <summary>
		/// Namespace Manager for the metadata.
		/// </summary>
		private readonly XmlNamespaceManager _metadataNsMgr;

	    #endregion

		#region Constructors

		/// <summary>
		/// Initializes a new instance of the IdentityProvider class.
		/// </summary>
        public IdentityProvider(XmlDocument metadata, XmlDocument extendedMetadata, Saml2Utils saml2Utils)
		{
		    try
			{
                _saml2Utils = saml2Utils;
				_metadata = metadata;
				_metadataNsMgr = new XmlNamespaceManager(_metadata.NameTable);
				_metadataNsMgr.AddNamespace("md", "urn:oasis:names:tc:SAML:2.0:metadata");
				_metadataNsMgr.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

				_extendedMetadata = extendedMetadata;
				_extendedMetadataNsMgr = new XmlNamespaceManager(_extendedMetadata.NameTable);
				_extendedMetadataNsMgr.AddNamespace("mdx", "urn:sun:fm:SAML:2.0:entityconfig");

				// Load now since a) it doesn't change and b) its a 
				// performance dog on Win 2003 64-bit.
				byte[] byteArray = Encoding.UTF8.GetBytes(EncodedSigningCertificate);
				SigningCertificate = new X509Certificate2(byteArray);
			}
			catch (XmlException xe)
			{
				throw new IdentityProviderException(Resources.IdentityProviderXmlException, xe);
			}
		}

	    #endregion

		#region Properties

		/// <summary>
		/// Gets the entity ID of this identity provider.
		/// </summary>
		public string EntityId
		{
			get
			{
				const string xpath = "/md:EntityDescriptor";
                return Saml2Utils.RequireAttributeValue(_metadata, _metadataNsMgr, xpath, "entityID").Trim();
			}
		}

	    /// <summary>
		/// Gets the encoded X509 certifcate located within the identity
		/// provider's metadata.
		/// </summary>
		public string EncodedSigningCertificate
		{
			get
			{
				const string xpath = "/md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor[@use='signing']/ds:KeyInfo/ds:X509Data/ds:X509Certificate";
                return Saml2Utils.RequireNodeText(_metadata, _metadataNsMgr, xpath).Trim();
			}
		}

		/// <summary>
		/// Gets the X509 signing certificate for this identity provider.
		/// </summary>
		public X509Certificate2 SigningCertificate { get; }

	    /// <summary>
		/// Gets the list of single log out service locations, if present,
		/// otherwise an empty list.
		/// </summary>
		public XmlNodeList SingleLogOutServiceLocations
		{
			get
			{
				const string xpath = "/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleLogoutService";
                var root = Saml2Utils.RequireRootElement(_metadata);
				var nodeList = root.SelectNodes(xpath, _metadataNsMgr);

				return nodeList;
			}
		}

		/// <summary>
		/// Gets the list of single sign on service locations, if present,
		/// otherwise an empty list.
		/// </summary>
		public XmlNodeList SingleSignOnServiceLocations
		{
			get
			{
				const string xpath = "/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService";
                var root = Saml2Utils.RequireRootElement(_metadata);
				var nodeList = root.SelectNodes(xpath, _metadataNsMgr);

				return nodeList;
			}
		}

	    /// <summary>
	    /// Gets a value indicating whether the extended metadata for
	    /// WantArtifactResolveSigned is true or false.
	    /// </summary>
	    public bool WantArtifactResolveSigned
	    {
	        get
	        {
	            const string xpath =
	                "/mdx:EntityConfig/mdx:IDPSSOConfig/mdx:Attribute[@name='wantArtifactResolveSigned']/mdx:Value";
                var text = Saml2Utils.TryGetNodeText(_extendedMetadata, _extendedMetadataNsMgr, xpath);
                return Saml2Utils.GetBoolean(text);
	        }
	    }

	    /// <summary>
		/// Gets a value indicating whether the metadata value for 
		/// WantAuthnRequestsSigned is true or false.
		/// </summary>
		public bool WantAuthnRequestsSigned
		{
			get
			{
				const string xpath = "/md:EntityDescriptor/md:IDPSSODescriptor";
                var value = Saml2Utils.TryGetAttributeValue(_metadata, _metadataNsMgr, xpath, "WantAuthnRequestsSigned");
                return Saml2Utils.GetBoolean(value);
			}
		}

		/// <summary>
		/// Gets a value indicating whether the metadata value for
		/// WantLogoutRequestSigned is true or false.
		/// </summary>
		/// <returns></returns>
		public bool WantLogoutRequestSigned
		{
			get
			{
				const string xpath = "/mdx:EntityConfig/mdx:IDPSSOConfig/mdx:Attribute[@name='wantLogoutRequestSigned']/mdx:Value";
                var text = Saml2Utils.TryGetNodeText(_extendedMetadata, _extendedMetadataNsMgr, xpath);
                return Saml2Utils.GetBoolean(text);
			}
		}

		/// <summary>
		/// Gets a value indicating whether the metadata value for
		/// WantLogoutResponseSigned is true or false.
		/// </summary>
		public bool WantLogoutResponseSigned
		{
			get
			{
				const string xpath = "/mdx:EntityConfig/mdx:IDPSSOConfig/mdx:Attribute[@name='wantLogoutResponseSigned']/mdx:Value";
                var text = Saml2Utils.TryGetNodeText(_extendedMetadata, _extendedMetadataNsMgr, xpath);
                return Saml2Utils.GetBoolean(text);
            }
		}

		#endregion

		#region Methods

		/// <summary>
		/// Obtain the artifact resolution service location based on the given binding.
		/// </summary>
		/// <param name="binding">The binding associated with the desired service.</param>
		/// <returns>Service location as defined in the metadata for the binding, null if not found.</returns>
		public string GetArtifactResolutionServiceLocation(string binding)
		{
			var xpath = new StringBuilder();
			xpath.Append("/md:EntityDescriptor/md:IDPSSODescriptor/md:ArtifactResolutionService");
			xpath.Append("[@Binding='");
			xpath.Append(binding);
			xpath.Append("']");

            return Saml2Utils.TryGetAttributeValue(_metadata, _metadataNsMgr, xpath.ToString(), "Location");
		}

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
		public string GetSingleLogoutServiceLocation(string binding)
		{
			var xpath = new StringBuilder();
			xpath.Append("/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleLogoutService");
			xpath.Append("[@Binding='");
			xpath.Append(binding);
			xpath.Append("']");

            return Saml2Utils.TryGetAttributeValue(_metadata, _metadataNsMgr, xpath.ToString(), "Location");
		}

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
		public string GetSingleLogoutServiceResponseLocation(string binding)
		{
			var xpath = $"/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleLogoutService[@Binding='{binding}']";
            return 
                Saml2Utils.TryGetAttributeValue(_metadata, _metadataNsMgr, xpath, "ResponseLocation")
                ??
                Saml2Utils.TryGetAttributeValue(_metadata, _metadataNsMgr, xpath, "Location");
		}

		/// <summary>
		/// Obtain the single sign on location based on the given binding.
		/// </summary>
		/// <param name="binding">The binding (should be made into constants / types).</param>
		/// <returns>Service location as defined in the metadata for the specified IDP and binding.</returns>
		public string GetSingleSignOnServiceLocation(string binding)
		{
            var xpath = $"/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService[@Binding='{binding}']";
            return Saml2Utils.TryGetAttributeValue(_metadata, _metadataNsMgr, xpath, "Location");
        }

		#endregion
    }
}