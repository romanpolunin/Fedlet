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
		private IFedletRepository _innerRepository;
		private FileSystemWatcher _fileSystemWatcher;
		private Timer _timer;
		private int _clearCacheAttempts = 0;

		private Dictionary<string, ICircleOfTrust> _cirlcesOfTrust;
		private ISamlServiceProvider _serviceProvider;
		private Dictionary<string, IIdentityProvider> _identityProviders;
		private string _homeFolder;

		/// <summary>
		/// Initializes a new instance of the <see cref="FileWatcherFedletRepository"/> class.
		/// </summary>
		/// <param name="homeFolder">The folder containing the configuration files.</param>
		public FileWatcherFedletRepository(string homeFolder)
		{
			_homeFolder = homeFolder;
			_innerRepository = new FileFedletRepository(homeFolder);
			_fileSystemWatcher = new FileSystemWatcher(homeFolder);
			_timer = new Timer(ReplaceCache);
			_fileSystemWatcher.Changed += ClearCache;
			_fileSystemWatcher.Created += ClearCache;
			_fileSystemWatcher.Deleted += ClearCache;
			_fileSystemWatcher.Renamed += ClearCache;
			_fileSystemWatcher.EnableRaisingEvents = true;
		}

		private void ReplaceCache(object state)
		{
			try
			{
				_clearCacheAttempts++;

				//don't replace any cached values unless all cached values can be replaced
				//  if a file is locked, the exception will reschedule replacing the cache
				var serviceProvider = _innerRepository.GetServiceProvider();
				var circleOfTrusts = _innerRepository.GetCircleOfTrusts();
				var identityProviders = _innerRepository.GetIdentityProviders();

				_serviceProvider = serviceProvider;
				_cirlcesOfTrust = circleOfTrusts;
				_identityProviders = identityProviders;

				_clearCacheAttempts = 0;
			}
			catch (Exception ex)
			{
				if (_clearCacheAttempts > 0 && _clearCacheAttempts % 100 == 0)
				{
					ex.Data["homeFolder"] = _homeFolder;
					LoggerFactory.GetLogger<ServiceProviderUtility>().Error(ex, "Unable to load configuration");
				}
				ClearCache(null, null);
			}
		}

		private void ClearCache(object sender, FileSystemEventArgs e)
		{
			_timer.Change(500, -1);
		}

		public Dictionary<string, ICircleOfTrust> GetCircleOfTrusts()
		{
			return _cirlcesOfTrust ?? (_cirlcesOfTrust = _innerRepository.GetCircleOfTrusts());
		}

		public ISamlServiceProvider GetServiceProvider()
		{
			return _serviceProvider ?? (_serviceProvider = _innerRepository.GetServiceProvider());
		}

		public Dictionary<string, IIdentityProvider> GetIdentityProviders()
		{
			return _identityProviders ?? (_identityProviders = _innerRepository.GetIdentityProviders());
		}
	}
}