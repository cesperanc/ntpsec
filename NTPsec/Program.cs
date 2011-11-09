using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ComponentModel;
using System.Threading;
using System.Net.Sockets;
using EI.SI;
using System.Net;

namespace NTPsec
{
    class Program
    {
        #region Console thread
        /// <summary>
        /// Thread to update the console clock
        /// </summary>
        private static Thread timerThread = null;

        /// <summary>
        /// Object to lock the console so only one thread can write text to the console at a given time
        /// </summary>
        static readonly object consoleLocker = new object();
        #endregion


        /// <summary>
        /// Main method
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            #region Variables instanciation

                TcpListener server = null;
                TcpClient client = null;
                NetworkStream stream = null;
                ProtocolSI protocol = null;
                byte[] msg;

                DateTime clientTime = DateTime.Now;
                //SymmetricAlgorithm sa = null;
                //RSACryptoServiceProvider rsaClient = null;
                //RSACryptoServiceProvider rsaServer = null;

                // TODO declarar aqui as variáveis necessárias para os protocolos de segurança

            #endregion

            try
            {
                #region Start the console timer thread

                    timerThread = new Thread(new ThreadStart(TimerUpdate));
                    timerThread.Name = "Console Timer";
                    timerThread.Start();

                #endregion


                WriteLine("SERVER_WITH_PROTOCOLSI - TbPractico 1: "+Environment.NewLine);

                #region Variables initialization

                    int port = 13000;

                    // Client/Server Protocol to SI
                    protocol = new ProtocolSI();

                    //    // Asymmetric Algorithm RSA
                    //    rsaClient = new RSACryptoServiceProvider();
                    //    rsaServer = new RSACryptoServiceProvider();


                    //    // Symmmetric Algorithm (TDES)
                    //    sa = TripleDESCryptoServiceProvider.Create();

                    // TODO definir aqui os valores para as variáveis necessárias para os protocolos de segurança

                #endregion


                #region Start the TCP Listener

                    // Start TcpListener
                    server = new TcpListener(IPAddress.Any, port);
                    server.ExclusiveAddressUse = true;
                    server.Start();

                #endregion

                // The Server runs in loop mode
                while (true)
                {

                    #region Waits for a TCP connection
                        
                        // If no client is connected
                        if (client == null || !client.Connected)
                        {
                            //Console.Clear();

                            // Waits for a client connection (blocking wait)
                            Write(Environment.NewLine+"Waiting for a connection... ");
                            client = server.AcceptTcpClient();
                            stream = client.GetStream();
                            Write("OK" + Environment.NewLine);

                            // TODO Inserir o código para fazer o handshake com o cliente. Colocando o código nesta àrea é possível gerir vários clientes em simultâneo.

                        }

                    #endregion

                    #region Receive the client time

                        // TODO decifrar, verificar integridade e autenticidade

                        if (stream.Read(protocol.Buffer, 0, protocol.Buffer.Length) <= 0)
                        {
                            client.Client.Disconnect(true);

                            WriteLine("No data received. Client connection was closed.");
                            continue;
                        }

                        #region Receive an ACK to close the client connection (optional)

                        // If we receive an ACK, the loop was completed and close the client connection
                        if (protocol.GetCmdType().Equals(ProtocolSICmdType.ACK))
                        {
                            client.Client.Disconnect(true);
                            stream.Close();
                            client = null;

                            WriteLine("ACK received. The client is OK for now, connection was closed.");
                            continue;
                        }
                        // If we received another request go on with the loop

                        #endregion

                        try
                        {
                            clientTime = new DateTime(Convert.ToInt64(protocol.GetStringFromData()));
                        }
                        catch (Exception)
                        {
                            client.Client.Disconnect(true);

                            WriteLine("Invalid time. Client connection was closed.");
                            continue;
                        }

                        WriteLine("Received a client with the time: " + clientTime.ToString("HH:mm:ss.f"));

                    #endregion

                    #region Send the server time as response

                        // TODO calcular a hash, assinar e cifrar a mensagem

                        Write("Sending the server time... ");
                        msg = protocol.Make(ProtocolSICmdType.DATA, DateTime.Now.Ticks.ToString());
                        stream.Write(msg, 0, msg.Length);
                        WriteLine("OK");

                    #endregion

                }
            }catch(Exception ex){
                Write("Error occurred: "+ex.Message);
            }finally
            {
                #region Terminate the console timer thread
                if (timerThread!=null){
                    // Cancel the thread
                    timerThread.Abort();
                    // Wait for the thread termination
                    timerThread.Join();
                    timerThread = null;
                }
                #endregion

                #region Terminate and dispose the TCP Listener, TCP Client and Stream

                if (stream != null)
                    stream.Close();
                if (client != null)
                    client.Close();
                if (server != null)
                    server.Stop();
                
                #endregion

                WriteLine(Environment.NewLine+"The server is now offline!"+Environment.NewLine);
            }
            WriteLine("End: Press a key...");
            Console.ReadKey();

        }

        #region Console timer methods

        /// <summary>
        /// Write the current time to the console
        /// </summary>
        private static void TimerUpdate()
        {
            do
            {
                Thread.Sleep(100);
                lock (consoleLocker)
                {
                    // Store the original cursor position
                    int left = Console.CursorLeft;
                    int top = Console.CursorTop;
                    Console.SetCursorPosition(0, 1);
                    Console.WriteLine(DateTime.Now.ToString("HH:mm:ss.f"));
                    Console.SetCursorPosition(left, top);
                }
            } while (true);
        }

        /// <summary>
        /// Write a line on the console respecting the console lock
        /// </summary>
        /// <param name="line">With the line to write</param>
        private static void WriteLine(String line){
            lock (consoleLocker)
            {
                Console.WriteLine(line);
            }
        }

        /// <summary>
        /// Write a text on the console respecting the console lock
        /// </summary>
        /// <param name="text">With the text to write</param>
        private static void Write(String text)
        {
            lock (consoleLocker)
            {
                Console.Write(text);
            }
        }

        #endregion
    }
}
