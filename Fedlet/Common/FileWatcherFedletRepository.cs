using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using Sun.Identity.Saml2;
using ISamlServiceProvider = Sun.Identity.Saml2.IServiceProvider;

namespace Sun.Identity.Common
{
	/// <summary>
	/// An implementation of <see cref="IFedletRepository"/> for retrieving data from config files.
	/// This repository will cache the values until a change is made to one of the config files.
	/// </summary>
	public class FileWatcherFedletRepository : IFedletRepository
	{
		private readonly IFedletRepository m_innerRepository;
		private readonly FileSystemWatcher m_fileSystemWatcher;
		private readonly Timer m_timer;
		private int m_clearCacheAttempts;

		private Dictionary<string, ICircleOfTrust> m_circlesOfTrust;
		private ISamlServiceProvider m_serviceProvider;
		private Dictionary<string, IIdentityProvider> m_identityProviders;
		private readonly string m_homeFolder;

        private readonly ILogger m_logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="FileWatcherFedletRepository"/> class.
        /// </summary>
        /// <param name="homeFolder">The folder containing the configuration files.</param>
        /// <param name="saml2Utils">Utilities</param>
        /// <param name="logger">Logger</param>
        public FileWatcherFedletRepository(string homeFolder, Saml2Utils saml2Utils, ILogger logger)
		{
			m_homeFolder = homeFolder;
            m_innerRepository = new FileFedletRepository(homeFolder, saml2Utils);
			m_fileSystemWatcher = new FileSystemWatcher(homeFolder);
			m_timer = new Timer(ReplaceCache);
			m_fileSystemWatcher.Changed += ClearCache;
			m_fileSystemWatcher.Created += ClearCache;
			m_fileSystemWatcher.Deleted += ClearCache;
			m_fileSystemWatcher.Renamed += ClearCache;
			m_fileSystemWatcher.EnableRaisingEvents = true;
            m_logger = logger;
		}

		private void ReplaceCache(object state)
		{
			try
			{
				m_clearCacheAttempts++;

				//don't replace any cached values unless all cached values can be replaced
				//  if a file is locked, the exception will reschedule replacing the cache
				var serviceProvider = m_innerRepository.GetServiceProvider();
				var circleOfTrusts = m_innerRepository.GetCircleOfTrusts();
				var identityProviders = m_innerRepository.GetIdentityProviders();

				m_serviceProvider = serviceProvider;
				m_circlesOfTrust = circleOfTrusts;
				m_identityProviders = identityProviders;

				m_clearCacheAttempts = 0;
			}
			catch (Exception ex)
			{
				if (m_clearCacheAttempts > 0 && m_clearCacheAttempts % 100 == 0)
				{
					ex.Data["homeFolder"] = m_homeFolder;
					m_logger.Error(ex, "Unable to load configuration");
				}
				ClearCache(null, null);
			}
		}

		private void ClearCache(object sender, FileSystemEventArgs e)
		{
			m_timer.Change(500, -1);
		}

	    /// <summary>Get all configuration information for all circles of trust.</summary>
	    public Dictionary<string, ICircleOfTrust> GetCircleOfTrusts()
		{
			return m_circlesOfTrust ?? (m_circlesOfTrust = m_innerRepository.GetCircleOfTrusts());
		}

	    /// <summary>Get all configuration information for the service provider.</summary>
	    public ISamlServiceProvider GetServiceProvider()
		{
			return m_serviceProvider ?? (m_serviceProvider = m_innerRepository.GetServiceProvider());
		}

	    /// <summary>Get all configuration information for all identity providers.</summary>
	    public Dictionary<string, IIdentityProvider> GetIdentityProviders()
		{
			return m_identityProviders ?? (m_identityProviders = m_innerRepository.GetIdentityProviders());
		}
	}
}