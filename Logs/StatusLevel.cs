

namespace auth.Logs
{
    /// <summary>
    /// Status levels: the color used in the message will depend on the level.
    /// </summary>
    public enum StatusLevel : int
    {
        /// <summary>
        /// Only information (neutral)
        /// </summary>
        [LocalizedDescription(nameof(Information), typeof(StatusLevel))]
        Information = 0,
        /// <summary>
        /// On success (green)
        /// </summary>
        [LocalizedDescription(nameof(Success), typeof(StatusLevel))]
        Success,
        /// <summary>
        /// Warning message (orange)
        /// </summary>
        [LocalizedDescription(nameof(Warning), typeof(StatusLevel))]
        Warning,
        /// <summary>
        /// Error message (red)
        /// </summary>
        [LocalizedDescription(nameof(Error), typeof(StatusLevel))]
        Error
    }
}

