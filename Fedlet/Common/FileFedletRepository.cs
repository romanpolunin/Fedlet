using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml;
using Sun.Identity.Properties;
using Sun.Identity.Saml2;
using Sun.Identity.Saml2.Exceptions;
using IServiceProvider = Sun.Identity.Saml2.IServiceProvider;

namespace Sun.Identity.Common
{
	/// <summary>
	/// The default implementation of <see cref="IFedletRepository"/> for retrieving data from config files.
	/// </summary>
	public class FileFedletRepository : IFedletRepository
	{
	    private readonly Saml2Utils m_saml2Utils;
	    private const string CircleOfTrustNameAttribute = "cot-name";
		private readonly DirectoryInfo m_homeFolder;

	    /// <summary>
	    /// Initializes a new instance of the <see cref="FileFedletRepository"/> class.
	    /// </summary>
	    /// <param name="homeFolder">The folder containing the configuration files.</param>
	    /// <param name="saml2Utils"></param>
	    public FileFedletRepository(string homeFolder, Saml2Utils saml2Utils)
		{
	        m_saml2Utils = saml2Utils;
	        if (!Directory.Exists(homeFolder))
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityHomeFolderNotFound);
			}

			m_homeFolder = new DirectoryInfo(homeFolder);
		}

		/// <summary>Get all configuration information for all circles of trust found in the home folder.</summary>
		public Dictionary<string, ICircleOfTrust> GetCircleOfTrusts()
		{
			var circleOfTrusts = m_homeFolder
				.GetFiles("fedlet*.cot")
				.Select(GetCircleOfTrust)
				.ToDictionary(c => c.Name);

			if (circleOfTrusts.Count == 0)
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtiltyCircleOfTrustsNotFound);
			}

			return circleOfTrusts;
		}

		private ICircleOfTrust GetCircleOfTrust(FileInfo fileInfo)
		{
			try
			{
				char[] separators = { '=' };
				var attributes = new NameValueCollection();

				var allLines = File.ReadAllLines(fileInfo.FullName);
				foreach (var line in allLines.Where(l => !string.IsNullOrEmpty(l)))
				{
					string[] tokens = line.Split(separators);
					string key = tokens[0];
					string value = tokens[1];
					attributes[key] = value;
				}

				if (string.IsNullOrEmpty(attributes[CircleOfTrustNameAttribute]))
				{
					throw new ServiceProviderUtilityException(
						Resources.CircleOfTrustNameNotFound + " in file " + fileInfo.FullName);
				}
				return new CircleOfTrust(attributes);
			}
			catch (DirectoryNotFoundException dnfe)
			{
				throw new CircleOfTrustException(Resources.CircleOfTrustDirNotFound, dnfe);
			}
			catch (FileNotFoundException fnfe)
			{
				throw new CircleOfTrustException(Resources.CircleOfTrustFileNotFound, fnfe);
			}
			catch (Exception e)
			{
				throw new CircleOfTrustException(Resources.CircleOfTrustUnhandledException, e);
			}
		}

		/// <summary>Get all configuration information for the service provider found in the home folder.</summary>
		public IServiceProvider GetServiceProvider()
		{
			try
			{
				var metadata = new XmlDocument();
				metadata.Load(Path.Combine(m_homeFolder.FullName, "sp.xml"));

				var extendedMetadata = new XmlDocument();
				extendedMetadata.Load(Path.Combine(m_homeFolder.FullName, "sp-extended.xml"));

				return new ServiceProvider(metadata, extendedMetadata, m_saml2Utils);
			}
			catch (DirectoryNotFoundException dnfe)
			{
				throw new ServiceProviderException(Resources.ServiceProviderDirNotFound, dnfe);
			}
			catch (FileNotFoundException fnfe)
			{
				throw new ServiceProviderException(Resources.ServiceProviderFileNotFound, fnfe);
			}
			catch (XmlException xe)
			{
				throw new ServiceProviderException(Resources.ServiceProviderXmlException, xe);
			}
		}

		/// <summary>Get all configuration information for all identity providers found in the home folder.</summary>
		public Dictionary<string, IIdentityProvider> GetIdentityProviders()
		{
			try
			{
				FileInfo[] files = m_homeFolder.GetFiles("idp*.xml");
				var identityProviders = files
					.Select(GetIdentityProvider)
					.Where(idp => idp != null)
					.ToDictionary(idp => idp.EntityId);

				if (identityProviders.Count <= 0)
				{
					throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityIdentityProvidersNotFound);
				}

				return identityProviders;

			}
			catch (DirectoryNotFoundException dnfe)
			{
				throw new IdentityProviderException(Resources.IdentityProviderDirNotFound, dnfe);
			}
			catch (FileNotFoundException fnfe)
			{
				throw new IdentityProviderException(Resources.IdentityProviderFileNotFound, fnfe);
			}
			catch (XmlException xe)
			{
				throw new IdentityProviderException(Resources.IdentityProviderXmlException, xe);
			}
		}

		private IIdentityProvider GetIdentityProvider(FileInfo metadataFile)
		{
			const string metadataFilePattern = "idp(.*).xml";
			const string extendedFilePattern = "idp{0}-extended.xml";

			if (!metadataFile.Exists)
			{
				return null;
			}

			// determine index
			Match m = Regex.Match(metadataFile.Name, metadataFilePattern);
			string fileIndex = null;
			if (m.Success)
			{
				fileIndex = m.Groups[1].Value;
			}

			string extendedFileName = string.Format(
				CultureInfo.InvariantCulture,
				extendedFilePattern,
				fileIndex ?? string.Empty);

			var extendedFile = new FileInfo(Path.Combine(m_homeFolder.FullName, extendedFileName));
			if (!extendedFile.Exists)
			{
				return null;
			}

			var metadata = new XmlDocument();
			metadata.Load(metadataFile.FullName);

			var extendedMetadata = new XmlDocument();
			extendedMetadata.Load(extendedFile.FullName);

            return new IdentityProvider(metadata, extendedMetadata, m_saml2Utils);
		}
	}
}