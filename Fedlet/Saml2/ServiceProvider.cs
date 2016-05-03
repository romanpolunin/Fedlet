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
 * $Id: ServiceProvider.cs,v 1.6 2010/01/26 01:20:14 ggennaro Exp $
 */

using System;
using System.Collections;
using System.Globalization;
using System.Text;
using System.Xml;
using Sun.Identity.Properties;
using Sun.Identity.Saml2.Exceptions;

namespace Sun.Identity.Saml2
{
	/// <summary>
	/// Represents all metadata for a Service Provider.
	/// </summary>
	public class ServiceProvider : IServiceProvider
	{
	    private readonly Saml2Utils _saml2Utils;

	    #region Members

		/// <summary>
		/// XML document representing the extended metadata for this Service 
		/// Provider.
		/// </summary>
		private readonly XmlDocument _extendedMetadata;

		/// <summary>
		/// Namespace Manager for the extended metadata.
		/// </summary>
		private readonly XmlNamespaceManager _extendedMetadataNsMgr;

		/// <summary>
		/// XML document representing the metadata for this Service Provider.
		/// </summary>
		private readonly XmlDocument _metadata;

		/// <summary>
		/// Namespace Manager for the metadata.
		/// </summary>
		private readonly XmlNamespaceManager _metadataNsMgr;

		#endregion

		#region Constructors

		/// <summary>
		/// Initializes a new instance of the ServiceProvider class. 
		/// </summary>
		public ServiceProvider(XmlDocument metadata, XmlDocument extendedMetadata, Saml2Utils saml2Utils)
		{
		    _saml2Utils = saml2Utils;
		    try
			{
				_metadata = metadata;
				_metadataNsMgr = new XmlNamespaceManager(metadata.NameTable);
				_metadataNsMgr.AddNamespace("md", "urn:oasis:names:tc:SAML:2.0:metadata");

				_extendedMetadata = extendedMetadata;
				_extendedMetadataNsMgr = new XmlNamespaceManager(extendedMetadata.NameTable);
				_extendedMetadataNsMgr.AddNamespace("mdx", "urn:sun:fm:SAML:2.0:entityconfig");
			}
			catch (XmlException xe)
			{
				throw new ServiceProviderException(Resources.ServiceProviderXmlException, xe);
			}
		}

	    #endregion

		#region Properties

        /// <summary>
        /// Gets a TimeSpan value to help tolerate NotOnOrAfter and NotBefore constraints checks
        /// due to SP-IdP time difference. Configuration file should contain integer number of seconds.
        /// </summary>
        public TimeSpan AssertionTimeSkew
        {
            get
            {
                const string xpath =
                    "/mdx:EntityConfig/mdx:SPSSOConfig/mdx:Attribute[@name='assertionTimeSkew']/mdx:Value";

                var value = Saml2Utils.TryGetNodeText(_extendedMetadata, _extendedMetadataNsMgr, xpath);
                int seconds;
                return value != null && Int32.TryParse(value, out seconds)
                    ? TimeSpan.FromSeconds(seconds)
                    : TimeSpan.FromSeconds(15);
            }
        }

        /// <summary>
		/// Gets a value indicating whether the standard metadata value for 
		/// AuthnRequestsSigned is true or false.
		/// </summary>
		public bool AuthnRequestsSigned
		{
			get
			{
				const string xpath = "/md:EntityDescriptor/md:SPSSODescriptor";
			    var value = Saml2Utils.TryGetAttributeValue(_metadata, _metadataNsMgr, xpath, "AuthnRequestsSigned");
                return Saml2Utils.GetBoolean(value);
			}
		}

		/// <summary>
		/// Gets the entity ID for this service provider.
		/// </summary>
		public string EntityId
		{
			get
			{
				const string xpath = "/md:EntityDescriptor";
			    return Saml2Utils.RequireAttributeValue(_metadata, _metadataNsMgr, xpath, "entityID");
			}
		}

		/// <summary>
		/// Gets the meta alias for this service provider.
		/// </summary>
		public string MetaAlias
		{
			get
			{
				const string xpath = "/mdx:EntityConfig/mdx:SPSSOConfig";
                return Saml2Utils.RequireAttributeValue(_extendedMetadata, _extendedMetadataNsMgr, xpath, "metaAlias");
			}
		}

		/// <summary>
		/// Gets the certificate alias, installed on this service provider, 
		/// for encryption.
		/// </summary>
		public string EncryptionCertificateAlias
		{
			get
			{
			    const string xpath = "/mdx:EntityConfig/mdx:SPSSOConfig/mdx:Attribute[@name='encryptionCertAlias']/mdx:Value";
			    return Saml2Utils.TryGetNodeText(_extendedMetadata, _extendedMetadataNsMgr, xpath);
			}
		}

		/// <summary>
		/// Gets a list of relay state URLs that are considered acceptable
		/// as a parameter in the various SAMLv2 profiles.
		/// </summary>
		public ArrayList RelayStateUrlList
		{
			get
			{
				var values = new ArrayList();
				const string xpath = "/mdx:EntityConfig/mdx:SPSSOConfig/mdx:Attribute[@name='relayStateUrlList']/mdx:Value";
				var root = Saml2Utils.RequireRootElement(_extendedMetadata);
				var nodeList = root.SelectNodes(xpath, _extendedMetadataNsMgr);

				if (nodeList != null)
				{
					foreach (XmlNode node in nodeList)
					{
						values.Add(node.InnerText.Trim());
					}
				}

				return values;
			}
		}

		/// <summary>
		/// Gets the certificate alias, installed on this service provider, 
		/// for signing.
		/// </summary>
		public string SigningCertificateAlias
		{
			get
			{
				const string xpath = "/mdx:EntityConfig/mdx:SPSSOConfig/mdx:Attribute[@name='signingCertAlias']/mdx:Value";
                return Saml2Utils.TryGetNodeText(_extendedMetadata, _extendedMetadataNsMgr, xpath);
            }
		}

		/// <summary>
		/// Gets a value indicating whether the extended metadata value for 
		/// wantArtifactResponseSigned is true or false.
		/// </summary>
		public bool WantArtifactResponseSigned
		{
			get
			{
				const string xpath = "/mdx:EntityConfig/mdx:SPSSOConfig/mdx:Attribute[@name='wantArtifactResponseSigned']/mdx:Value";
                var value = Saml2Utils.TryGetNodeText(_extendedMetadata, _extendedMetadataNsMgr, xpath);
                return Saml2Utils.GetBoolean(value);
			}
		}

		/// <summary>
		/// Gets a value indicating whether the standard metadata value for 
		/// WantAssertionsSigned is true or false.
		/// </summary>
		public bool WantAssertionsSigned
		{
			get
			{
				const string xpath = "/md:EntityDescriptor/md:SPSSODescriptor";
			    var value = Saml2Utils.TryGetAttributeValue(_metadata, _metadataNsMgr, xpath, "WantAssertionsSigned");
                return Saml2Utils.GetBoolean(value);
			}
		}

		/// <summary>
		/// Gets a value indicating whether the extended metadata value for 
		/// wantPOSTResponseSigned is true or false.
		/// </summary>
		public bool WantPostResponseSigned
		{
			get
			{
				const string xpath = "/mdx:EntityConfig/mdx:SPSSOConfig/mdx:Attribute[@name='wantPOSTResponseSigned']/mdx:Value";
                var value = Saml2Utils.TryGetNodeText(_extendedMetadata, _extendedMetadataNsMgr, xpath);
                return Saml2Utils.GetBoolean(value);
			}
		}

		/// <summary>
		/// Gets a value indicating whether the extended metadata value for 
		/// wantLogoutRequestSigned is true or false.
		/// </summary>
		public bool WantLogoutRequestSigned
		{
			get
			{
				const string xpath = "/mdx:EntityConfig/mdx:SPSSOConfig/mdx:Attribute[@name='wantLogoutRequestSigned']/mdx:Value";
                var value = Saml2Utils.TryGetNodeText(_extendedMetadata, _extendedMetadataNsMgr, xpath);
                return Saml2Utils.GetBoolean(value);
            }
		}

		/// <summary>
		/// Gets a value indicating whether the extended metadata value for 
		/// wantLogoutResponseSigned is true or false.
		/// </summary>
		public bool WantLogoutResponseSigned
		{
			get
			{
				const string xpath = "/mdx:EntityConfig/mdx:SPSSOConfig/mdx:Attribute[@name='wantLogoutResponseSigned']/mdx:Value";
                var value = Saml2Utils.TryGetNodeText(_extendedMetadata, _extendedMetadataNsMgr, xpath);
                return Saml2Utils.GetBoolean(value);
            }
		}

		#endregion

		#region Methods

		/// <summary>
		/// Obtain the assertion consumer service location based on the given binding.
		/// </summary>
		/// <param name="binding">The binding associated with the desired consumer service.</param>
		/// <returns>Service location as defined in the metadata for the binding, null if not found.</returns>
		public string GetAssertionConsumerServiceLocation(string binding)
		{
			var xpath = new StringBuilder();
			xpath.Append("/md:EntityDescriptor/md:SPSSODescriptor/md:AssertionConsumerService");
			xpath.Append("[@Binding='");
			xpath.Append(binding);
			xpath.Append("']");

            return Saml2Utils.TryGetAttributeValue(_metadata, _metadataNsMgr, xpath.ToString(), "Location");
		}

		/// <summary>
		/// Obtain the assertion consumer service location based on the given binding.
		/// </summary>
		/// <param name="binding">The binding associated with the desired consumer service.</param>
		/// <param name="index">The index associated with the desired consumer service.</param>
		/// <returns>Service location as defined in the metadata for the binding, null if not found.</returns>
		public string GetAssertionConsumerServiceLocation(string binding, string index)
		{
			var xpath = new StringBuilder();
			xpath.Append("/md:EntityDescriptor/md:SPSSODescriptor/md:AssertionConsumerService");
			xpath.Append("[@Binding='");
			xpath.Append(binding);
			xpath.Append("' and index='");
			xpath.Append(index);
			xpath.Append("']");

            return Saml2Utils.TryGetAttributeValue(_metadata, _metadataNsMgr, xpath.ToString(), "Location");
        }

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
		public int GetAuthLevelFromAuthnContextClassRef(string classReference)
		{
			int authLevel = -1;

			XmlNodeList nodes = GetAuthnContextClassRefMap();
			//IEnumerator i = nodes.GetEnumerator();

			//while (i.MoveNext())
            foreach (XmlNode value in nodes)
			{
				//var value = (XmlNode) i.Current;
				char[] separators = {'|'};
				string[] results = value.InnerText.Split(separators);
				if (results.Length > 1 && results[0] == classReference)
				{
					authLevel = Convert.ToInt32(results[1], CultureInfo.InvariantCulture);
					break;
				}
			}

			return authLevel;
		}

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
		public string GetAuthnContextClassRefFromAuthLevel(int authLevel)
		{
			// Set to default if not found.
			var classReference = Saml2Constants.AuthClassRefPasswordProtectedTransport;

			var nodes = GetAuthnContextClassRefMap();

            foreach (XmlNode value in nodes)
			{
				//var value = (XmlNode) i.Current;
				char[] separators = {'|'};
				string[] results = value.InnerText.Split(separators);
				if (results.Length > 1 && Convert.ToInt32(results[1], CultureInfo.InvariantCulture) == authLevel)
				{
					classReference = results[0];
					break;
				}
			}

			return classReference;
		}

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
		public string GetExportableMetadata(bool signMetadata)
		{
			var exportableXml = (XmlDocument) _metadata.CloneNode(true);
			XmlNode entityDescriptorNode
				= exportableXml.SelectSingleNode("/md:EntityDescriptor", _metadataNsMgr);

			if (entityDescriptorNode == null)
			{
				throw new Saml2Exception(Resources.ServiceProviderEntityDescriptorNodeNotFound);
			}

			if (signMetadata && string.IsNullOrEmpty(SigningCertificateAlias))
			{
				throw new Saml2Exception(Resources.ServiceProviderCantSignMetadataWithoutCertificateAlias);
			}

			if (signMetadata)
			{
				var descriptorId = exportableXml.CreateAttribute("ID");
                descriptorId.Value = _saml2Utils.GenerateId();
				entityDescriptorNode.Attributes.Append(descriptorId);

                _saml2Utils.SignXml(SigningCertificateAlias, exportableXml, descriptorId.Value, true);
			}

			return exportableXml.InnerXml;
		}

		/// <summary>
		/// <para>
		/// Returns the XmlNodeList of "Values" maintained in the service
		/// provider's extended metadata under the attribute named
		/// "spAuthncontextClassrefMapping".  For example:
		/// </para>
		/// <para>
		///  &lt;Attribute name="spAuthncontextClassrefMapping"&gt;
		///    &lt;Value&gt;urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport|0|default&lt;/Value&gt;
		///  &lt;/Attribute&gt;
		/// </para>
		/// </summary>
		/// <returns>Returns the XmlNodeList of values found in the metadata.</returns>
		private XmlNodeList GetAuthnContextClassRefMap()
		{
			var xpath = new StringBuilder();
			xpath.Append("/mdx:EntityConfig/mdx:SPSSOConfig/mdx:Attribute");
			xpath.Append("[@name='spAuthncontextClassrefMapping']/mdx:Value");

			var root = Saml2Utils.RequireRootElement(_extendedMetadata);
			var nodes = root.SelectNodes(xpath.ToString(), _extendedMetadataNsMgr);
			return nodes;
		}

		#endregion
	}
}