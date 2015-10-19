namespace Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models
{
    using Common.Logging;

    using Raven.Client;

    public class RavenDbTokenRepositoryConfiguration
    {
        /// <summary>
        /// Initializes a new instance of the Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models.RavenDbTokenRepositoryConfiguration class.
        /// </summary>
        /// <param name="store">The store.</param>
        /// <param name="log">The logger.</param>
        public RavenDbTokenRepositoryConfiguration(IDocumentStore store, ILog log)
        {
            this.Log = log;
            this.DocumentStore = store.Initialize();

            // Make sure the required indexes are created
            Raven.Client.Indexes.IndexCreation.CreateIndexes(this.GetType().Assembly, store);
        }

        /// <summary>Gets the store.</summary>
        /// <value>The store.</value>
        public IDocumentStore DocumentStore { get; private set; }

        /// <summary>Gets the log.</summary>
        /// <value>The log.</value>
        public ILog Log { get; private set; }
    }
}