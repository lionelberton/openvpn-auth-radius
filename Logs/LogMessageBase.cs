using System;
using System.IO;

namespace auth.Logs
{
    /// <summary>
    /// base log message class
    /// </summary>
    public class LogMessageBase
    {
        /// <summary>
        /// The path of the application log
        /// </summary>
        private readonly string _applicationLogPath;
        /// <summary>
        /// lock to make public function thread safe.
        /// </summary>
        protected readonly object Lock = new object();


        /// <summary>
        /// The maximum status level width.
        /// </summary>
        private readonly int _maxStatusLevelWidth;

        /// <summary>
        /// Initializes a new instance of the <see cref="LogMessageBase" /> class.
        /// </summary>
        /// <param name="applicationLogPath">the application log path</param>
        public LogMessageBase(string applicationLogPath)
        {
            _maxStatusLevelWidth = 44 + Math.Max(Math.Max(LocalizedDescriptionAttribute.GetEnumDescription(StatusLevel.Error).Length, LocalizedDescriptionAttribute.GetEnumDescription(StatusLevel.Warning).Length),
                                    Math.Max(LocalizedDescriptionAttribute.GetEnumDescription(StatusLevel.Success).Length, LocalizedDescriptionAttribute.GetEnumDescription(StatusLevel.Information).Length));
            _applicationLogPath = applicationLogPath;
        }

        /// <summary>
        /// Log display message
        /// </summary>
        /// <param name="message">the message</param>
        /// <param name="level">the status level</param>
        public virtual void LogDisplayMessage(string message, StatusLevel level)
        {
            LogSilentMessage(message, level);
        }

        /// <summary>
        /// Log the silent message
        /// </summary>
        /// <param name="message">the message</param>
        /// <param name="level">the status level</param>
        public virtual void LogSilentMessage(string message, StatusLevel level)
        {
            lock (Lock)
            {
                LogSilentMessageExtraAction(level);

                var s = string.Format("{0}  [{1}]>", DateTimeOffset.Now.ToString("dd-MMM-yyyy HH:mm:ss.fffffff zzz"), LocalizedDescriptionAttribute.GetEnumDescription(level));
                //on calcule la plus grande longueur de texte
                //ça rend le texte plus lisible quand tout est aligné.
                s = s.PadRight(_maxStatusLevelWidth);
                // on rajoute des espaces pour aligner le paragraphe lorsque le message a plusieurs lignes.
                s += message.Replace("\n", "\n" + new string(' ', s.Length));

                LogSilentMessageAppendLog(s);
                AppendLogFile(s + Environment.NewLine);
            }
        }
        /// <summary>
        /// Extra action for the silent logges messages 
        /// </summary>
        /// <param name="level">the status level</param>
        protected virtual void LogSilentMessageExtraAction(StatusLevel level)
        {

        }

        /// <summary>
        /// Extra action for the silent logged message
        /// </summary>
        /// <param name="message">the message</param>
        protected virtual void LogSilentMessageAppendLog(string message)
        {

        }

        /// <summary>
        /// Appends the log file.
        /// </summary>
        /// <param name="text">The text.</param>
        public void AppendLogFile(string text)
        {
            try
            {
                using (var fs = new FileStream(_applicationLogPath, FileMode.Append, FileAccess.Write))
                {
                    using (var sw = new StreamWriter(fs))
                    {
                        sw.Write(text);
                    }
                }
            }
            catch
            {
                //Ne pas logguer là: on est dans une exception qui ne peut pas logguer: on entre dans une boucle infinie si on fait ça
                //L'erreur sera dans le log d'erreur
            }
        }
    }
}

