using System.IO;
using System.Text;

namespace auth.Logs
{
    /// <summary>
    /// A base application log writer class
    /// </summary>
    public class ApplicationLogBase : TextWriter
    {
        /// <summary>
        /// buffer to store messages until WriteLine is called.
        /// </summary>
        private readonly StringBuilder _sb;

        /// <summary>
        /// The level of the message to be displayed.
        /// </summary>
        private readonly StatusLevel _level;

        /// <summary>
        /// True if message are information sent directly to the log. false if messages are errors that needs to be displayed to users.
        /// </summary>
        private readonly bool _isSilent;

        /// <summary>
        /// The instance that implement IlogMessage to be used
        /// </summary>
        private readonly LogMessageBase _logMessageInstance;

        /// <summary>
        /// Creates a new empty ApplicationLogWriterBase
        /// <param name="isSilent">indicate if it's a silent log</param>
        /// <param name="level">the status level</param>
        /// <param name="logMessageInstance">the ILogMessage</param>
        /// </summary>
        public ApplicationLogBase(bool isSilent, StatusLevel level, LogMessageBase logMessageInstance)
        {
            _sb = new StringBuilder();
            _isSilent = isSilent;
            _level = level;
            _logMessageInstance = logMessageInstance;
        }

        /// <summary>
        /// returns the encoding used to write text.
        /// </summary>
        public override Encoding Encoding
        {
            get { return Encoding.Default; }
        }
        /// <summary>
        /// Append the string to the buffer.
        /// </summary>
        /// <param name="value">the value</param>
        public override void Write(string value)
        {
            _sb.Append(value);
        }
        /// <summary>
        /// Flush the current content of the buffer to the application log.
        /// </summary>
        public override void WriteLine()
        {
            if (_sb.Length > 0)
            {
                var s = _sb.ToString();
                if (_isSilent)
                {
                    _logMessageInstance.LogSilentMessage(s, _level);
                }
                else
                {
                    _logMessageInstance.LogDisplayMessage(s, _level);
                }
                _sb.Clear();
            }
        }

        /// <summary>
        /// Writes an entire line to the application log prepending it with the current content of the buffer.
        /// </summary>
        /// <param name="value">the value</param>
        public override void WriteLine(string value)
        {
            string s;
            if (_sb.Length > 0)
            {
                s = _sb.ToString() + value;
                _sb.Clear();
            }
            else
            {
                s = value;
            }
            if (_isSilent)
            {
                _logMessageInstance.LogSilentMessage(s, _level);
            }
            else
            {
                _logMessageInstance.LogDisplayMessage(s, _level);
            }
        }
    }
}

