using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Sockets;
using EI.SI;
using System.Net;
using System.Threading;

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
                int numOfBytes;
                DateTime clientTimeA = DateTime.Now;
                DateTime clientTimeB = DateTime.Now;
                DateTime serverTimeX = DateTime.Now;
                DateTime serverTimeY = DateTime.Now;
                //SymmetricAlgorithm sa = null;
                //RSACryptoServiceProvider rsaClient = null;
                //RSACryptoServiceProvider rsaServer = null;

                // TODO declarar aqui as variáveis necessárias para os protocolos de segurança

            #endregion

            try
            {
                Console.WriteLine("CLIENT_WITH_PROTOCOLSI - TbPractico 1\n");

                #region Variables initialization

                    // Server TCP/IP address and port
                    IPAddress serverAddr = IPAddress.Parse("127.0.0.1");
                    int serverPort = 13000;

                    // Client/Server Protocol to SI
                    protocol = new ProtocolSI();

                    //    // Asymmetric Algorithm RSA
                    //    rsaClient = new RSACryptoServiceProvider();
                    //    rsaServer = new RSACryptoServiceProvider();

                    //    // Symmmetric Algorithm (TDES) & defenitions
                    //    sa = TripleDESCryptoServiceProvider.Create();
                    //    //sa.GenerateKey();  
                    //    //sa.GenerateIV();
                    //    sa.Mode = CipherMode.CBC;
                    //    sa.Padding = PaddingMode.PKCS7;

                    // TODO definir aqui os valores para as variáveis necessárias para os protocolos de segurança

                #endregion

                #region Connect with the Server

                    // Connect to Server ...
                    Console.Write("Connecting to server... ");
                    client = new TcpClient();
                    client.Connect(serverAddr, serverPort);
                    stream = client.GetStream();
                    Console.WriteLine("OK"+Environment.NewLine);

                    // TODO Inserir o código para fazer o handshake com o servidor. Possivelmente a chave pública tem de ser carregada automaticamente a partir de um ficheiro XML a colocar junto do executável da aplicação ou hardcoded nas aplicações (mais simples). A chave pública e privada do cliente pode ser criada em runtime ou hardcoded também em cada uma das aplicações.

                #endregion

                #region Send the client time A

                    // TODO calcular a hash, assinar e cifrar a mensagem

                    Console.Write("Sending the client time A... ");
                    clientTimeA = DateTime.Now;
                    msg = protocol.Make(ProtocolSICmdType.DATA, clientTimeA.Ticks.ToString());
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
                        serverTimeX = new DateTime(Convert.ToInt64(protocol.GetStringFromData()));
                    }
                    catch (Exception)
                    {
                        throw new Exception("Invalid time. Client connection was closed.");
                    }

                    Console.WriteLine("Received a server time: " + serverTimeX.ToString("HH:mm:ss.f"));

                #endregion
                    Thread.Sleep(500);
                #region Send the client time B

                    // TODO calcular a hash, assinar e cifrar a mensagem

                    Console.Write("Sending the client time B... ");
                    clientTimeB = DateTime.Now;
                    msg = protocol.Make(ProtocolSICmdType.DATA, clientTimeB.Ticks.ToString());
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
                        serverTimeY = new DateTime(Convert.ToInt64(protocol.GetStringFromData()));
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

                #region Present the results
                    // TODO Apresentar os resultados com base nos valores de clientTimeA, clientTimeB, serverTimeX e serverTimeY
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
            Console.WriteLine("End: Press a key...");
            Console.ReadKey();
        }
    }
}
