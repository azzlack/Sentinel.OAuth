namespace Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Interfaces
{
    public interface ISqlServerRepositoryConfiguration
    {
        /// <summary>Gets the connection string.</summary>
        /// <value>The connection string.</value>
        string ConnectionString { get; }
    }
}