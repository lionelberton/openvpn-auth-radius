namespace auth
{
    /// <summary>
    /// The server configuration
    /// </summary>
    public class ServerConfiguration
    {
        /// <summary>
        /// Gets or sets the server name
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets the auth port
        /// </summary>
        public uint Authport { get; set; }

        /// <summary>
        /// Gets or sets the Acct port
        /// </summary>
        public uint Acctport { get; set; }

        /// <summary>
        /// Gets or sets the waiting time in seconds
        /// </summary>
        public int Wait { get; set; }

        /// <summary>
        /// Gets or sets the number of retries
        /// </summary>
        public int Retries { get; set; }

        /// <summary>
        /// Gets or sets the shared secret
        /// </summary>
        public string Sharedsecret { get; set; }  
    }
}
