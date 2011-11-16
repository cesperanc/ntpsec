using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Sockets;
using EI.SI;
using System.Net;
using System.Threading;
using System.Security.Cryptography;
using System.IO;
using System.Xml;

namespace NTPsecClient
{
    class Program
    {
        static void Main(string[] args)
        {
            #region Variables instanciation

                TcpClient client = null;
                NetworkStream stream = null;
                ProtocolSI protocol = null;
                byte[] msg;
                byte[] hash;
                byte[] signHash;
                byte[] cypherKey;
                byte[] clearData;    
                byte[] cipherData;
                int numOfBytes;
                DateTime clientTimeA = DateTime.Now;
                DateTime clientTimeB = DateTime.Now;
                DateTime serverTimeX = DateTime.Now;
                DateTime serverTimeY = DateTime.Now;
                long delay = 0;
                long offset = 0;
                SymmetricAlgorithm sa = null;
                SymmetricsSI symmSI = null;
                RSACryptoServiceProvider rsaClient = null;
                RSACryptoServiceProvider rsaServer = null;


                // TODO declarar aqui as variáveis necessárias para os protocolos de segurança

            #endregion

            try
            {
                Console.WriteLine("CLIENT_WITH_PROTOCOLSI - TbPractico 1\n");



                IPAddress serverAddr;
                string serverIP=null;
                do
                {
                    Console.Write("Please insert a valid ip address: ");
                    serverIP = Console.ReadLine();

                } while (!IPAddress.TryParse(serverIP, out serverAddr));

                Console.WriteLine("Trying to connect to " + serverIP + ":13000");

                #region Variables initialization

                    // Server TCP/IP address and port
                    //serverAddr = IPAddress.Parse(serverIP);
                    int serverPort = 13000;

                    // Client/Server Protocol to SI
                    protocol = new ProtocolSI();

                    //    // Asymmetric Algorithm RSA
                        rsaClient = new RSACryptoServiceProvider();
                        rsaServer = new RSACryptoServiceProvider();

                        // Symmmetric Algorithm (TDES) & defenitions
                        sa = TripleDESCryptoServiceProvider.Create();
                        //sa.GenerateKey();  
                        //sa.GenerateIV();
                        sa.Mode = CipherMode.CBC;
                        sa.Padding = PaddingMode.PKCS7;


                        SHA1CryptoServiceProvider sha1 = new SHA1CryptoServiceProvider();
                        // create Encrytor/Decryptor
                        symmSI = new SymmetricsSI(sa);

                    // TODO definir aqui os valores para as variáveis necessárias para os protocolos de segurança

                #endregion

                #region Read or Create the server Keys

                if (File.Exists("serverPublicKey.xml"))
                {
                    XmlDocument xmlPublicKey = new XmlDocument();
                    xmlPublicKey.Load("serverPublicKey.xml");
                    rsaServer.FromXmlString(xmlPublicKey.InnerXml);
                }
                else
                {
                    Console.WriteLine("Can't find server public key, will exit now.");
                    Console.ReadKey();
                    System.Environment.Exit(1);
                }


                #endregion

                #region Connect with the Server

                    // Connect to Server ...
                    Console.Write("Connecting to server... ");
                    client = new TcpClient();
                    client.Connect(serverAddr, serverPort);
                    stream = client.GetStream();
                    Console.WriteLine("OK"+Environment.NewLine);

                    // Inserir o código para fazer o handshake com o servidor. Possivelmente a chave pública tem de ser carregada automaticamente a partir de um ficheiro XML a colocar junto do executável da aplicação ou hardcoded nas aplicações (mais simples). A chave pública e privada do cliente pode ser criada em runtime ou hardcoded também em cada uma das aplicações.
                    #region Autentication (virtual  login)
                        // Send public key
                        Console.Write("Secure the connection... ");
                        msg = protocol.Make(ProtocolSICmdType.PUBLIC_KEY, rsaClient.ToXmlString(false));
                        stream.Write(msg, 0, msg.Length);
                            
                        // get server key
                        numOfBytes = stream.Read(protocol.Buffer, 0, protocol.Buffer.Length);
                        cypherKey = protocol.GetData();
                        sa.Key = rsaClient.Decrypt(cypherKey, true);

                        // send ack to server
                        msg = protocol.Make(ProtocolSICmdType.ACK);
                        stream.Write(msg, 0, msg.Length);


                        // compare SECRET_KEY hash
                        stream.Read(protocol.Buffer, 0, protocol.Buffer.Length);
                        signHash = protocol.GetData();
                        hash = sha1.ComputeHash(cypherKey);
                        bool result = rsaServer.VerifyData(hash, sha1, signHash);
                        if (!result)
                        {
                            Console.WriteLine("The SECRET_KEY hash don't match i will exit now.");
                            Console.ReadKey();
                            System.Environment.Exit(1);
                        }
                
                        // the hash match so send another ack to get IV key
                        msg = protocol.Make(ProtocolSICmdType.ACK);
                        stream.Write(msg, 0, msg.Length);

                        // Receive the cyper IV from server
                        numOfBytes = stream.Read(protocol.Buffer, 0, protocol.Buffer.Length);
                        byte[] cypherIV = protocol.GetData();
                        sa.IV = rsaClient.Decrypt(cypherIV, true);

                        // send ack to server
                        msg = protocol.Make(ProtocolSICmdType.ACK);
                        stream.Write(msg, 0, msg.Length);

                        // compare IV hash
                        stream.Read(protocol.Buffer, 0, protocol.Buffer.Length);
                        signHash = protocol.GetData();
                        //sha1 = new SHA1CryptoServiceProvider();
                        hash = sha1.ComputeHash(cypherIV);

                        result = rsaServer.VerifyData(hash, sha1, signHash);
                        if (!result)
                        {
                            Console.WriteLine("The IV hash don't match i will exit now.");
                            Console.ReadKey();
                            System.Environment.Exit(1);
                        }


                        



                        Console.WriteLine("ok");
                    #endregion

                #endregion

                #region Send the client time A

                    // TODO calcular a hash, assinar e cifrar a mensagem

                    Console.Write("Sending the client time A... ");
                    clientTimeA = DateTime.Now;

                    // data
                    clearData =  Encoding.UTF8.GetBytes(clientTimeA.Ticks.ToString());
                    // Cypher data
                    cipherData = symmSI.Encrypt(clearData);
                
                    msg = protocol.Make(ProtocolSICmdType.SYM_CIPHER_DATA, cipherData);
                    stream.Write(msg, 0, msg.Length);

                    // Receive ack from server 
                    stream.Read(protocol.Buffer, 0, protocol.Buffer.Length);
                    
                    // Send hash to server
                    hash = sha1.ComputeHash(cipherData);
                    signHash = rsaClient.SignData(hash, sha1);
                    msg = protocol.Make(ProtocolSICmdType.DIGITAL_SIGNATURE, signHash);
                    stream.Write(msg, 0, msg.Length);

                    Console.WriteLine("OK");

                #endregion

                #region Receive the server time X

                    // TODO decifrar, verificar integridade e autenticidade
                    
                    if (stream.Read(protocol.Buffer, 0, protocol.Buffer.Length) <= 0)
                    {
                        throw new Exception("No data received. Client connection was closed.");
                    }

                    try
                    {
                        // Read server cypher time
                        cipherData = protocol.GetData();
                        clearData = symmSI.Decrypt(cipherData);

                        // Send ack so server send HASH
                        msg = protocol.Make(ProtocolSICmdType.ACK);
                        stream.Write(msg, 0, msg.Length);

                        // get and check server signed hash
                        stream.Read(protocol.Buffer, 0, protocol.Buffer.Length);
                        signHash = protocol.GetData();
                        hash = sha1.ComputeHash(cipherData);

                        result = rsaServer.VerifyData(hash, sha1, signHash);
                        if (!result)
                        {
                            Console.WriteLine("Invalid signature. Client connection was closed.");
                            Console.ReadKey();
                            System.Environment.Exit(1);
                        }

                        serverTimeX = new DateTime(Convert.ToInt64(ProtocolSI.ToString(clearData)));
                    }
                    catch (Exception)
                    {
                        throw new Exception("Invalid time. Client connection was closed.");
                    }

                    Console.WriteLine("Received a server time: " + serverTimeX.ToString("HH:mm:ss.f"));

                #endregion
                    // Uncoment to put delay
                    //Thread.Sleep(2500);
                #region Send the client time B

                    // TODO calcular a hash, assinar e cifrar a mensagem

                    Console.Write("Sending the client time B... ");
                    clientTimeB = DateTime.Now;

                    // data
                    clearData = Encoding.UTF8.GetBytes(clientTimeB.Ticks.ToString());
                    // Cypher data
                    cipherData = symmSI.Encrypt(clearData);

                    msg = protocol.Make(ProtocolSICmdType.SYM_CIPHER_DATA, cipherData);
                    stream.Write(msg, 0, msg.Length);

                    // Receive ack from server 
                    stream.Read(protocol.Buffer, 0, protocol.Buffer.Length);

                    // Send hash to server
                    hash = sha1.ComputeHash(cipherData);
                    signHash = rsaClient.SignData(hash, sha1);
                    msg = protocol.Make(ProtocolSICmdType.DIGITAL_SIGNATURE, signHash);
                    stream.Write(msg, 0, msg.Length);

                    Console.WriteLine("OK");




                #endregion

                #region Receive the server time Y

                    // TODO decifrar, verificar integridade e autenticidade

                    if (stream.Read(protocol.Buffer, 0, protocol.Buffer.Length) <= 0)
                    {
                        throw new Exception("No data received. Client connection was closed.");
                    }

                    try
                    {
                        // Read server cypher time
                        cipherData = protocol.GetData();
                        clearData = symmSI.Decrypt(cipherData);

                        // Send ack so server send HASH
                        msg = protocol.Make(ProtocolSICmdType.ACK);
                        stream.Write(msg, 0, msg.Length);

                        // get and check server signed hash
                        stream.Read(protocol.Buffer, 0, protocol.Buffer.Length);
                        signHash = protocol.GetData();
                        hash = sha1.ComputeHash(cipherData);

                        result = rsaServer.VerifyData(hash, sha1, signHash);
                        if (!result)
                        {
                            Console.WriteLine("Invalid signature. Client connection was closed.");
                            Console.ReadKey();
                            System.Environment.Exit(1);
                        }
                        serverTimeY = new DateTime(Convert.ToInt64(ProtocolSI.ToString(clearData)));
                    }
                    catch (Exception)
                    {
                        throw new Exception("Invalid time. Client connection was closed.");
                    }

                    Console.WriteLine("Received a server time: " + serverTimeY.ToString("HH:mm:ss.f"));

                #endregion

                #region Send an ACK to release the server for another client

                    Console.Write("Sending an ACK... ");
                    msg = protocol.Make(ProtocolSICmdType.ACK);
                    stream.Write(msg, 0, msg.Length);
                    Console.WriteLine("OK");

                #endregion
                
                #region delay and offset calc
                    delay = (clientTimeB.Ticks - clientTimeA.Ticks) - (serverTimeY.Ticks - serverTimeX.Ticks);
                    offset = (serverTimeX.Ticks - clientTimeA.Ticks + serverTimeY.Ticks - clientTimeB.Ticks)  / 2;
                #endregion
                
                #region Present the results
                    Console.WriteLine();
                    Console.WriteLine();
                    Console.WriteLine("Local time: "+clientTimeA.ToString("HH:mm:ss.f"));
                    Console.WriteLine("Server time: " + serverTimeY.ToString("HH:mm:ss.f"));
                    Console.WriteLine("Delay: " + delay.ToString());
                    DateTime setTime = new DateTime(serverTimeY.Ticks + (delay));
                    Console.WriteLine("Time to set: " + setTime.ToString("HH:mm:ss.f"));

                    do
                    {
                        Thread.Sleep(10);
                        // Store the original cursor position
                        int left = Console.CursorLeft;
                        int top = Console.CursorTop;
                        Console.SetCursorPosition(0, 18);
                        DateTime currentTime = new DateTime(DateTime.Now.Ticks + (offset));
                        Console.WriteLine(currentTime.ToString("HH:mm:ss.f"));
                        Console.SetCursorPosition(left, top);
                        //Console.WriteLine("End: Press a key...");

                    } while (!Console.KeyAvailable);

                #endregion
            }
            catch (Exception ex)
            {
                Console.Write("Error occurred: " + ex.Message);
            }
            finally
            {

                #region Terminate and dispose the TCP Client and Stream

                if (stream != null)
                    stream.Close();
                if (client != null)
                    client.Close();

                #endregion

                Console.WriteLine(Environment.NewLine + "Connection with server was closed!" + Environment.NewLine);
            }

            Console.ReadKey();
        }

        /// <summary>
        /// Converts a byte array into a <c>string</c> (hexadecimal format)
        /// </summary>
        /// <param name="bytes">Bytes to covert to <c>string</c></param>
        /// <returns>Hexadecimal <c>string</c></returns>
        public string ToHexString(byte[] bytes)
        {
            int i;
            StringBuilder sb = new StringBuilder();
            for (i = 0; i < bytes.Length; i++)
                sb.Append(string.Format("{0,2:X2} ", bytes[i]));
            return sb.ToString();
        }
    }
}
