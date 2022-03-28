using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using auth.Logs;
using auth.Properties;
using Radius;
using Radius.Atributes;
using Radius.Enums;

namespace auth
{
    public class Program
    {
        /// <summary>
        /// The default log folder
        /// </summary>
        private static string _defaultLogFolder;
        /// <summary>
        /// The _error log file name
        /// </summary>
        public const string ErrorLogPrefixName = "errorlog";

        /// <summary>
        /// Application Log file name.
        /// </summary>
        public const string ApplicationLogPrefixName = "applicationlog";


        /// <summary>
        /// The Application log writter instance
        /// </summary>
        private static LogMessageBase _applicationLogWriterInstance;

        /// <summary>
        /// The contents
        /// </summary>
        private enum FileContent
        {
            /// <summary>
            /// The user name
            /// </summary>
            userName = 0,
            /// <summary>
            /// The password
            /// </summary>
            /// <remarks>if the double factor is used, the second line contains password and double facor encoded in base 64. If not the password in clear</remarks>
            password = 1,
        }

        /// <summary>
        /// The authetication data
        /// </summary>
        private enum AuthenticationData
        {
            /// <summary>
            /// SCRV1
            /// </summary>
            SCRV1 = 0,
            /// <summary>
            /// The password encoded in base 64
            /// </summary>
            PasswordBased64,
            /// <summary>
            /// The response encoded in base 64
            /// </summary>
            ResponseBased64
        }

        /// <summary>
        /// Enum that represents the Acct status type
        /// </summary>
        private enum Acct_Status_Type
        {
            Start = 1,
            Stop = 2,
            InterimUpdate = 3,
            AccountingOn = 7,
            AccountingOff = 8
        }

        /// <summary>
        /// Enum to indicates the method with which the user's declared identity was verified
        /// </summary>
        private enum Acct_Authentic
        {
            Radius = 1,
            Local = 2,
            Remote
        }

        /// <summary>
        /// Enums to indicates the acct terminate cause
        /// </summary>
        private enum Acct_Terminate_Cause
        {
            /// <summary>
            /// The user initiated the termination by logging off
            /// </summary>
            UserRequest = 1,
            LostCarrier = 2,
            LostService = 3,
            IdleTimeout = 4,
            SessionTimeout = 5,
            AdminReset = 6,
            AdminReboot = 7,
            PortError = 8,
            NASError = 9,
            NASRequest = 10,
            NASReboot = 11,
            PortUnneeded = 12,
            PortPreempted = 13
        }

        /// <summary>
        /// Constant to name the use of authentication mode
        /// </summary>
        private const string Authentication = "Authentication";

        /// <summary>
        /// Constant to name the use of Client connect mode
        /// </summary>
        private const string ClientConnect = "ClientConnect";

        /// <summary>
        /// Constant to name the use of Client disconnect mode
        /// </summary>
        private const string ClientDisconnect = "ClientDisconnect";

        /// <summary>
        /// Entry point
        /// </summary>
        /// <param name="args">Contains the path of the file with connection info (using via file)</param>
        /// <returns></returns>
        public static int Main(string[] args)
        {
            _defaultLogFolder = Settings.Default.LogFolder;

            if (string.IsNullOrEmpty(_defaultLogFolder))
            {
                Log.ErrorLog.WriteLine("No folder defined for the logs.");
                return 5;
            }

            InitLogger();
            if (args != null)
            {
                switch (args[0])
                {
                    case Authentication:
                        return OpenVPNAuthenticate(args);
                    case ClientConnect:
                        return SendAccountingRequest(Acct_Status_Type.Start);
                    case ClientDisconnect:
                        return SendAccountingRequest(Acct_Status_Type.Stop);
                    default:
                        Log.ErrorLog.WriteLine("First argument is not correct. Use 'Authentication', 'ClientConnect' or 'ClientDisconnect' ");
                        return 8;

                }
            }
            else
            {
                Log.ErrorLog.WriteLine("atgument cannot be null. Use 'Authentication', 'ClientConnect' or 'ClientDisconnect' ");
                return 8;
            }
        }


        /// <summary>
        /// Autheticate the connection
        /// </summary>
        /// <param name="args">the arguments</param>
        /// <returns></returns>
        private static int OpenVPNAuthenticate(string[] args)
        {
            //The first argument is used to determine which type of request is sent by OpenVPN
            //as we are using via file option, the second argument contains the path of a temporary file
            var path = args[1];

            if (!File.Exists(path))
            {
                Log.ErrorLog.WriteLine($"file is not existing at path {path}");
                return 1;
            }

            //The file must contains two lines
            var array = File.ReadAllLines(path);
            if (array.Length != 2)
            {
                Log.ErrorLog.WriteLine($"file {path} is not correct");
                return 6;
            }

            //user name is on first row
            var userName = array[(int)FileContent.userName];
            string password;
            string doubleFactor = null;
            //If the second row strat with SCRV1, the MFA is activated
            if (array[(int)FileContent.password].Substring(0, 5) == "SCRV1")
            {
                //we need to split on ':' to retrieve password and MFA code
                //structure SCRV1:base64_pass:base64_response
                var secondLineData = array[(int)FileContent.password].Split(':');
                if (secondLineData.Length == 3)
                {
                    password = Encoding.UTF8.GetString(Convert.FromBase64String(secondLineData[(int)AuthenticationData.PasswordBased64]));
                    doubleFactor = Encoding.UTF8.GetString(Convert.FromBase64String(secondLineData[(int)AuthenticationData.ResponseBased64]));
                }
                else
                {
                    Log.ErrorLog.WriteLine("Error in authentication. The password row doesn't contains the requested elements.");
                    return 7;
                }
            }
            else
            {
                password = array[(int)FileContent.password];
            }


            if (Config.Settings == null)
            {
                Log.ErrorLog.WriteLine("The plugin configuration is empty/unreadable");
                return 2;
            }

            if (Config.Settings.Servers == null || Config.Settings.Servers.Count == 0)
            {
                Log.ErrorLog.WriteLine("No servers found in config");
                return 3;
            }

            var res = Parallel.ForEach(Config.Settings.Servers.Cast<ServerElement>(), (server, state) =>
            {
                Log.InformationLog.WriteLine(string.Format("server name = {0} , retries = {1}, wait = {2}, autport = {3}",
                                                            server.Name, server.retries, server.wait, server.authport));

                var rc = new RadiusClient(server.Name, server.sharedsecret, server.wait * 1000, server.authport, server.acctport);

                Log.InformationLog.WriteLine("Radius client is initializated.");

                try
                {
                    var authPacket = rc.Authenticate(userName, password);
                    if (Config.Settings.NAS_IDENTIFIER != null)
                    {
                        authPacket.SetAttribute(new RadiusAttribute(RadiusAttributeType.NAS_IDENTIFIER, Encoding.ASCII.GetBytes(Config.Settings.NAS_IDENTIFIER)));
                    }

                    authPacket.SetAttribute(new RadiusAttribute(RadiusAttributeType.NAS_PORT_TYPE, Utils.GetNetworkBytes((int)NasPortType.ASYNC)));

                    var receivedPacket = rc.SendAndReceivePacket(authPacket, server.retries).Result;

                    if (receivedPacket == null)
                    {
                        Log.ErrorLog.WriteLine("Can't contact remote radius server {0}!", server.Name);
                    }


                    Log.InformationLog.WriteLine("List of the attributes received");
                    foreach (var attribute in receivedPacket.Attributes)
                    {
                        Log.InformationLog.WriteLine(attribute.Type.ToString() + " " + attribute.Value);
                    }

                    if (receivedPacket != null)
                    {
                        //Depending of the packet response type, we have to manage different cases
                        switch (receivedPacket.PacketType)
                        {
                            //MFA not activated. The access is granted
                            case RadiusCode.ACCESS_ACCEPT:
                                if (!string.IsNullOrEmpty(doubleFactor))
                                {
                                    Log.SilentWarningLog.WriteLine("Double factor must be activated for the user {0}", userName);
                                }
                                state.Stop();
                                break;
                            //A radius challenge is requested
                            case RadiusCode.ACCESS_CHALLENGE:
                                Log.InformationLog.WriteLine("Starting the access challenge for user {0}", userName);
                                var packet = new RadiusPacket(RadiusCode.ACCESS_REQUEST);
                                packet.SetAttribute(receivedPacket.Attributes.First(x => x.Type == RadiusAttributeType.STATE));
                                packet.SetAuthenticator(server.sharedsecret);
                                byte[] data = Utils.EncodePapPassword(Encoding.ASCII.GetBytes(doubleFactor), packet.Authenticator, server.sharedsecret);
                                packet.SetAttribute(new RadiusAttribute(RadiusAttributeType.USER_PASSWORD, data));
                                var returnPacketForChallenge = rc.SendAndReceivePacket(packet).Result;

                                if (returnPacketForChallenge == null)
                                {
                                    Log.ErrorLog.WriteLine("Return packet for RADIUS challenge is null for user {0}.", userName);
                                }
                                else
                                {
                                    Log.InformationLog.WriteLine("Packet type: " + returnPacketForChallenge.PacketType);
                                    //If the Radius challenge is completed, the packet type must be access_accept
                                    if (returnPacketForChallenge.PacketType == RadiusCode.ACCESS_ACCEPT)
                                    {
                                        state.Stop();
                                    }
                                }
                                break;
                            //Other cases
                            default:
                                Log.InformationLog.WriteLine("Packet type received is {0}", receivedPacket.PacketType.ToString());
                                break;
                        }


                    }

                }
                catch (Exception ex)
                {
                    Log.ErrorLog.WriteLine(ex);
                }

            });

            if (res.IsCompleted)
            {
                //On a parcouru tous les srveurs et on n'a rien trouvé
                Log.ErrorLog.WriteLine(string.Format("Authentication failed for: {0}", userName));
                return 4;
            }
            else
            {
                Log.SuccessLog.WriteLine(string.Format("Authentication success for user {0}", userName));
                return 0;
            }
        }



        /// <summary>
        /// Send an accounting request
        /// </summary>
        /// <param name="acct_Status_Type"> the type (start or stop)</param>
        private static int SendAccountingRequest(Acct_Status_Type acct_Status_Type)
        {
            //The first argument is used to determine which type of request is sent by OpenVPN
            //In accounting mode (used by client_connect and client disconnect, the second and third parameters are the common name and the IP Address of the requester
            var commonName = Environment.GetEnvironmentVariable("common_name");
            var ipAddress = Environment.GetEnvironmentVariable("trusted_ip");

            if (!string.IsNullOrEmpty(commonName) && !string.IsNullOrEmpty(ipAddress))
            {
                try
                {

                    var res = Parallel.ForEach(Config.Settings.Servers.Cast<ServerElement>(), (server, state) =>
                    {
                        var rc = new RadiusClient(server.Name, server.sharedsecret, server.wait * 1000, server.authport, server.acctport);

                        var accountingPacket = new RadiusPacket(RadiusCode.ACCOUNTING_REQUEST);
                        //Int Attributes must be Big-endian cf https://www.ietf.org/rfc/rfc2865.txt page 24
                        if (Config.Settings.NAS_IDENTIFIER != null)
                        {
                            accountingPacket.SetAttribute(new RadiusAttribute(RadiusAttributeType.NAS_IDENTIFIER, Encoding.ASCII.GetBytes(Config.Settings.NAS_IDENTIFIER)));
                        }
                        accountingPacket.SetAttribute(new RadiusAttribute(RadiusAttributeType.NAS_PORT_TYPE, Utils.GetNetworkBytes((int)NasPortType.ASYNC)));
                        accountingPacket.SetAttribute(new RadiusAttribute(RadiusAttributeType.ACCT_STATUS_TYPE,Utils.GetNetworkBytes( (int)acct_Status_Type)));
                        accountingPacket.SetAttribute(new RadiusAttribute(RadiusAttributeType.ACCT_SESSION_ID, Encoding.UTF8.GetBytes(commonName)));
                        accountingPacket.SetAttribute(new RadiusAttribute(RadiusAttributeType.USER_NAME, Encoding.UTF8.GetBytes(commonName)));
                        accountingPacket.SetAttribute(new RadiusAttribute(RadiusAttributeType.ACCT_AUTHENTIC, Utils.GetNetworkBytes((int)Acct_Authentic.Radius)));
                        var address = ipAddress.Split(".");
                        var ipAsByteArray=new byte[4];
                        for( var i=0;i<address.Length;i++)
                        {
                            ipAsByteArray[i] = (Byte)int.Parse(address[i]);
                        }
                        accountingPacket.SetAttribute(new RadiusAttribute(RadiusAttributeType.FRAMED_IP_ADDRESS, ipAsByteArray));
                        accountingPacket.SetAttribute(RadiusAttribute.CreateString(RadiusAttributeType.CALLING_STATION_ID, ipAddress));

                        if (acct_Status_Type == Acct_Status_Type.Stop)
                        {
                            accountingPacket.SetAttribute(new RadiusAttribute(RadiusAttributeType.ACCT_TERMINATE_CAUSE, Utils.GetNetworkBytes((int)Acct_Terminate_Cause.UserRequest)));
                        }

                        Log.InformationLog.WriteLine("Set the authenticator");
                        accountingPacket.SetAuthenticator(server.sharedsecret);

                        var accountingPacketResponse = rc.SendAndReceivePacket(accountingPacket ,server.retries).Result;

                        if (accountingPacketResponse != null)
                        {
                            if (accountingPacketResponse.PacketType != RadiusCode.ACCOUNTING_RESPONSE)
                            {
                                Log.ErrorLog.WriteLine("The response packet type for the accounting request of type {0} for user {1} is not correct on server {2}.",
                                    (int)acct_Status_Type, commonName, server.Name);
                                foreach (var attribute in accountingPacketResponse.Attributes)
                                {
                                    Log.InformationLog.WriteLine(attribute.Type.ToString() + " " + attribute.Value);
                                }
                            }
                            else
                            {
                                Log.InformationLog.WriteLine("List of the attributes received for the accounting request of type {0} for user {1} on server {2}.",
                                    (int)acct_Status_Type, commonName, server.Name);
                                foreach (var attribute in accountingPacketResponse.Attributes)
                                {
                                    Log.InformationLog.WriteLine(attribute.Type.ToString() + " " + attribute.Value);
                                }
                                state.Stop();
                            }
                        }
                        else
                        {
                            Log.ErrorLog.WriteLine("accounting response is null on server {0}", server.Name);
                        }
                    });

                    if (res.IsCompleted)
                    {
                        //On a parcouru tous les serveurs et on n'a rien trouvé
                        Log.ErrorLog.WriteLine(string.Format("Accounting {0}  failed for: {1}", acct_Status_Type == Acct_Status_Type.Start ? "Start" : "Stop", commonName));
                        //Mettre une valeur > 0 quand debuggge fini
                        return 0;
                    }
                    else
                    {
                        Log.SuccessLog.WriteLine(string.Format("Accounting {0} success for user {1}", acct_Status_Type == Acct_Status_Type.Start ? "Start" : "Stop", commonName));
                        return 0;
                    }
                }
                catch (Exception ex)
                {
                    Log.ErrorLog.WriteLine("Error during sending accounting request");
                    Log.ErrorLog.WriteLine(ex);
                    //Mettre une valeur > 0 quand debuggge fini
                    return 0;
                }
            }
            else
            {
                if (string.IsNullOrEmpty(commonName))
                {
                    Log.ErrorLog.WriteLine("The environment variable for common_name is null. Unable to send an accounting request.");
                }
                if (string.IsNullOrEmpty(ipAddress))
                {
                    Log.ErrorLog.WriteLine("The environment variable for trusted_ip is null. Unable to send an accounting request.");
                }
                //Mettre une valeur > 0 quand debuggge fini
                return 0;
            }

        }

        /// <summary>
        /// Init the logger
        /// </summary>
        private static void InitLogger()
        {
            Directory.CreateDirectory(_defaultLogFolder);
            var version = Assembly.GetExecutingAssembly().GetName().Version;
            var pid = Process.GetCurrentProcess().Id;
            var maxN = GetMaxFileNumber(_defaultLogFolder, ErrorLogPrefixName, ApplicationLogPrefixName);
            maxN++;
            var applicationLogPath = Path.Combine(_defaultLogFolder, $"{ApplicationLogPrefixName}_{maxN:000}_{version}_{pid:00000}.txt");
            var errorLogPath = Path.Combine(_defaultLogFolder, $"{ErrorLogPrefixName}_{maxN:000}_{version}_{pid:00000}.txt");

            new ExceptionLogger(errorLogPath);
            _applicationLogWriterInstance = new LogMessageBase(applicationLogPath);

            DeleteOldLogFiles(_defaultLogFolder, ErrorLogPrefixName, 30, 30);
            DeleteOldLogFiles(_defaultLogFolder, ApplicationLogPrefixName, 30, 30);

            Log.Instance.InformationLogBase = new ApplicationLogBase(true, StatusLevel.Information, _applicationLogWriterInstance);
            Log.Instance.SilentWarningLogBase = new ApplicationLogBase(true, StatusLevel.Warning, _applicationLogWriterInstance);
            Log.Instance.DisplayWarningLogBase = new ApplicationLogBase(true, StatusLevel.Warning, _applicationLogWriterInstance);
            Log.Instance.ErrorLogBase = new ApplicationLogBase(true, StatusLevel.Error, _applicationLogWriterInstance);
            Log.Instance.SuccessLogBase = new ApplicationLogBase(true, StatusLevel.Success, _applicationLogWriterInstance);
        }

        /// <summary>
        /// Deletes the old log files.
        /// </summary>
        /// <param name="folderPath">The folder path.</param>
        /// <param name="filePrefix">The file prefix.</param>
        /// <param name="days">The days.</param>
        /// <param name="maxCount">The maximum count.</param>
        private static void DeleteOldLogFiles(string folderPath, string filePrefix, int days, int maxCount)
        {
            var filesWithDates = new Dictionary<string, DateTimeOffset>();
            var thresholdDate = DateTime.Now.AddDays(-days);
            foreach (var filePath in Directory.EnumerateFiles(folderPath, filePrefix + "*.txt", SearchOption.TopDirectoryOnly))
            {
                var fileName = Path.GetFileName(filePath);
                var fileSplit = fileName.Split('_');
                if (fileSplit.Length == 4 && fileSplit[0].Equals(filePrefix, StringComparison.InvariantCulture))
                {
                    var lastTime = File.GetLastWriteTime(filePath);
                    if (lastTime < thresholdDate)
                    {
                        DeleteFile(filePath);
                    }
                    else
                    {
                        filesWithDates[filePath] = lastTime;
                    }
                }
            }
            foreach (var fileWithDate in filesWithDates.OrderByDescending(fwd => fwd.Value).Skip(maxCount))
            {
                DeleteFile(fileWithDate.Key);
            }
        }

        /// <summary>
        /// Deletes the file.
        /// </summary>
        /// <param name="filePath">The file path.</param>
        private static void DeleteFile(string filePath)
        {
            try
            {
                File.Delete(filePath);
            }
#pragma warning disable RECS0022 // A catch clause that catches System.Exception and has an empty body
            catch
#pragma warning restore RECS0022 // A catch clause that catches System.Exception and has an empty body
            {
                //si on peut pas supprimé c'est pas grave, c'est juste pour nettoyer. L'admin le fera à la main.
            }
        }

        /// <summary>
        /// Gets the maximum file number.
        /// </summary>
        /// <param name="folderPath">The folder path.</param>
        /// <param name="errorLogPrefix">the error log prefix</param>
        /// <param name="applicationLogPrefix">the application log prefix</param>
        /// <returns></returns>
        private static int GetMaxFileNumber(string folderPath, string errorLogPrefix, string applicationLogPrefix)
        {
            int maxN = 0;
            // on gère les noms de fichiers suivants
            // nom_nnn_v.v.v.v_pid.txt
            // nom peut être soit errorlog ou applicationlog
            // nnn est un numéro incrémenter à chaque lancement de flowers.
            // v.v.v.v est le numero de version de flowers
            // pid est le process id de flowers.
            foreach (var filePath in Directory.EnumerateFiles(folderPath, "*.txt", SearchOption.TopDirectoryOnly))
            {
                var fileName = Path.GetFileName(filePath);
                var fileSplit = fileName.Split('_');
                if (fileSplit.Length == 4)
                {
                    if (fileSplit[0].Equals(errorLogPrefix, StringComparison.InvariantCulture)
                        || fileSplit[0].Equals(applicationLogPrefix, StringComparison.InvariantCulture))
                    {
                        if (int.TryParse(fileSplit[1], out var nnn))
                        {
                            maxN = Math.Max(maxN, nnn);
                        }
                    }
                }
            }
            return maxN;
        }
    }
}
