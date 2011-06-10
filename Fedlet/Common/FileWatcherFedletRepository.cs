using System.Collections.Generic;
using System.IO;
using Sun.Identity.Saml2;

namespace Sun.Identity.Common
{
	/// <summary>
	/// An implementation of <see cref="IFedletRepository"/> for retrieving data from config files.
	/// This repository will cache the values until a change is made to one of the config files.
	/// </summary>
	public class FileWatcherFedletRepository : IFedletRepository
	{
		private FileFedletRepository _innerRepository;
		private Dictionary<string, CircleOfTrust> _cirlcesOfTrust;
		private IServiceProvider _serviceProvider;
		private Dictionary<string, IdentityProvider> _identityProviders;
		private FileSystemWatcher _fileSystemWatcher;

		/// <summary>
		/// Initializes a new instance of the <see cref="FileWatcherFedletRepository"/> class.
		/// </summary>
		/// <param name="homeFolder">The folder containing the configuration files.</param>
		public FileWatcherFedletRepository(string homeFolder)
		{
			_innerRepository = new FileFedletRepository(homeFolder);
			_fileSystemWatcher = new FileSystemWatcher(homeFolder);
			_fileSystemWatcher.Changed += ClearCache;
			_fileSystemWatcher.Created += ClearCache;
			_fileSystemWatcher.Deleted += ClearCache;
		}

		private void ClearCache(object sender, FileSystemEventArgs e)
		{
			_cirlcesOfTrust = null;
			_serviceProvider = null;
			_identityProviders = null;
		}

		public Dictionary<string, CircleOfTrust> GetCircleOfTrusts()
		{
			return _cirlcesOfTrust ?? (_cirlcesOfTrust = _innerRepository.GetCircleOfTrusts());
		}

		public IServiceProvider GetServiceProvider()
		{
			return _serviceProvider ?? (_serviceProvider = _innerRepository.GetServiceProvider());
		}

		public Dictionary<string, IdentityProvider> GetIdentityProviders()
		{
			return _identityProviders ?? (_identityProviders = _innerRepository.GetIdentityProviders());
		}
	}
}