using System;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using WindowsCredentialManager.Win32;
using WindowsCredentialManager.Win32.Types;

namespace WindowsCredentialManager
{
  public sealed class RawStringCredentials : Credential
  {
    public RawStringCredentials(string targetName) 
      : base(targetName, CredentialType.Generic)
    {
    }
    public string? UserName { get; set; }

    public string? Password { get; set; }

    internal override unsafe void Deserialize(CREDENTIALW_RAW* credentialW)
    {
      UserName = Marshal.PtrToStringUni(credentialW->UserName);

      var bytes = new byte[credentialW->BlobSize];
      Marshal.Copy(credentialW->Blob, bytes, 0, credentialW->BlobSize);
      Password = GzipDecompress(bytes);
    }

    internal override void Serialize(ref CREDENTIALW credentialW)
    {
      credentialW.UserName = UserName;
      
      var compressedBytes = GzipCompress(Password);
      credentialW.Blob = Password == null
        ? null
        : new RawBytesBlob(compressedBytes);
    }

    private string GzipDecompress(byte[] bytes)
    {
      var compressedStream = new MemoryStream(bytes);
      var output = new MemoryStream();
      var gzipStream = new GZipStream(compressedStream, CompressionMode.Decompress);
      gzipStream.CopyTo(output);
      output.Seek(0, SeekOrigin.Begin);
      return System.Text.Encoding.UTF8.GetString(output.ToArray());
    }

    private static byte[] GzipCompress(string input)
    {
      var inputStream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(input));
      var compressedStream = new MemoryStream();
      var gzipStream = new GZipStream(compressedStream, CompressionLevel.Optimal);
      inputStream.CopyTo(gzipStream);
      gzipStream.Flush();
      compressedStream.Seek(0, SeekOrigin.Begin);
      return compressedStream.ToArray();
    }
  }

  internal class RawBytesBlob : SecureBlob
  {
    private readonly int _size;

    public RawBytesBlob(byte[] bytes)
    {
      handle = Marshal.AllocHGlobal(bytes.Length);
      _size = bytes.Length;

      Marshal.Copy(bytes, 0, handle, bytes.Length);
    }

    public override int Size => _size;
    protected override bool ReleaseHandle()
    {
      Marshal.Copy(new byte[Size], 0, handle, Size);
      Marshal.FreeHGlobal(handle);
      handle = IntPtr.Zero;
      return true;
    }
  }
}
