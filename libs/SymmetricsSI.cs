using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace EI.SI
{
    /// <summary>
    /// Class to implement SYMMETRIC Encrytion/Decryption.
    /// </summary>
    /// <remarks>
    /// EI.SI :: by Rui Ferreira & Nuno Costa
    /// Version 1.1
    /// Last Update: 26-10-2011
    /// </remarks>
    public partial class SymmetricsSI: IDisposable
    {
        // Track whether Dispose has been called.
        private bool disposed = false;

        // Class atributes
        ICryptoTransform encryptor = null;
        ICryptoTransform decryptor = null;
        SymmetricAlgorithm sa = null;


        #region Constructors
        /// <summary>
        /// Constructor: the correct symmetric Algorithm should be passed.        
        /// </summary>
        /// <param name="sa">Symmetric Algorithm with the correct Secret Key</param>
        public SymmetricsSI(SymmetricAlgorithm sa)
        {
            this.sa = sa;
        }
        #endregion        



        #region Public Methods

        /// <summary>
        /// Encrypts data with the Symmetric Algorithm.
        /// Note: can be used in any famework version
        /// </summary>
        /// <param name="plainbytes">Plain data</param>
        /// <returns>Cipher data</returns>
        public byte[] Encrypt(byte[] plainbytes)
        {
            MemoryStream ms = null;
            CryptoStream cs = null;
            try
            {
                if (this.encryptor == null)
                    this.encryptor = sa.CreateEncryptor();

                ms = new MemoryStream();
                cs = new CryptoStream(ms, this.encryptor, CryptoStreamMode.Write);
                cs.Write(plainbytes, 0, plainbytes.Length);
                cs.Close();
                return ms.ToArray();
            }
            catch (Exception ex)
            {
                throw new Exception("SymmetricsSI.Encrypt :: ", ex);
            }
            finally
            {
                if (cs != null)
                    cs.Clear();
                if (ms != null)
                    ms.Dispose();
            }
        }


        /// <summary>
        /// Encrypts data with the Symmetric Algorithm.
        /// Note: should be used only in the framework 4 or higher
        /// </summary>
        /// <param name="plainbytes">Plain data</param>
        /// <returns>Cipher data</returns>
        public byte[] Encrypt2(byte[] plainbytes)
        {
            MemoryStream msPlainData = null;
            MemoryStream msCipherData = null;
            CryptoStream cs = null;
            try
            {
                if (this.encryptor == null)
                    this.encryptor = sa.CreateEncryptor();

                msPlainData = new MemoryStream(plainbytes);
                msCipherData = new MemoryStream();
                cs = new CryptoStream(msPlainData, this.encryptor, CryptoStreamMode.Read);
                cs.CopyTo(msCipherData);
                cs.Flush();
                if (!cs.HasFlushedFinalBlock)
                    cs.FlushFinalBlock();
                return msCipherData.ToArray();
            }
            catch (Exception ex)
            {
                throw new Exception("SymmetricsSI.Encrypt2 :: ", ex);
            }
            finally
            {
                if (cs != null)
                    cs.Clear();               
                if (msCipherData != null)
                    msCipherData.Dispose();
                if (msPlainData != null)
                    msPlainData.Dispose();
            }
        }



        /// <summary>
        /// Decrypts data with the Symmetric Algorithm.
        /// Note: can be used in any famework version
        /// </summary>
        /// <param name="plainbytes">Cipher data</param>
        /// <returns>Plain data</returns>
        public byte[] Decrypt(byte[] cipherData)
        {
            MemoryStream ms = null;
            CryptoStream cs = null;
            try
            {
                if (this.decryptor == null)
                    this.decryptor = sa.CreateDecryptor();

                ms = new MemoryStream(cipherData);
                cs = new CryptoStream(ms, this.decryptor, CryptoStreamMode.Read);
                byte[] plainbytes = new byte[ms.Length];
                int numPlainBytes = cs.Read(plainbytes, 0, plainbytes.Length);
                cs.Close();
                Array.Resize(ref plainbytes, numPlainBytes);
                return plainbytes;
            }
            catch (Exception ex)
            {
                throw new Exception("SymmetricsSI.Decrypt :: ", ex);
            }
            finally
            {
                if (cs != null)
                    cs.Clear();
                if (ms != null)
                    ms.Dispose();
            }
        }

        /// <summary>
        /// Decrypts data with the Symmetric Algorithm.
        /// Note: should be used only in the framework 4 or higher
        /// </summary>
        /// <param name="plainbytes">Cipher data</param>
        /// <returns>Plain data</returns>
        public byte[] Decrypt2(byte[] cipherData)
        {
            MemoryStream msCipher = null;
            MemoryStream msPlain = null;
            CryptoStream cs = null;
            try
            {
                if (this.decryptor == null)
                    this.decryptor = sa.CreateDecryptor();

                msCipher = new MemoryStream(cipherData);
                msPlain = new MemoryStream();
                cs = new CryptoStream(msCipher, this.decryptor, CryptoStreamMode.Read);
                cs.CopyTo(msPlain);
                cs.Flush();
                if (!cs.HasFlushedFinalBlock)
                    cs.FlushFinalBlock();
                return msPlain.ToArray();
            }
            catch (Exception ex)
            {
                throw new Exception("SymmetricsSI.Decrypt2 :: ", ex);
            }
            finally
            {
                if (cs != null)
                    cs.Clear();
                if (msCipher != null)
                    msCipher.Dispose();
                if (msPlain != null)
                    msPlain.Dispose();
            }
        }


        #endregion


        #region IDisposable Members
        // Implement IDisposable.
        // Do not make this method virtual.
        // A derived class should not be able to override this method.
        public void Dispose()
        {
            Dispose(true);
            // This object will be cleaned up by the Dispose method.
            // Therefore, you should call GC.SupressFinalize to
            // take this object off the finalization queue
            // and prevent finalization code for this object
            // from executing a second time.
            GC.SuppressFinalize(this);
        }

        // Dispose(bool disposing) executes in two distinct scenarios.
        // If disposing equals true, the method has been called directly
        // or indirectly by a user's code. Managed and unmanaged resources
        // can be disposed.
        // If disposing equals false, the method has been called by the
        // runtime from inside the finalizer and you should not reference
        // other objects. Only unmanaged resources can be disposed.
        private void Dispose(bool disposing)
        {
            // Check to see if Dispose has already been called.
            if (!this.disposed)
            {
                // If disposing equals true, dispose all managed
                // and unmanaged resources.
                if (disposing)
                {
                    // Dispose managed resources.
                    if (this.encryptor != null)
                        this.encryptor.Dispose();
                    if (this.decryptor != null)
                        this.decryptor.Dispose();
                }

                // Call the appropriate methods to clean up unmanaged resources here.
                // If disposing is false, only the following code is executed.


                // Note disposing has been done.
                disposed = true;
            }
        }
        #endregion

    }
}
