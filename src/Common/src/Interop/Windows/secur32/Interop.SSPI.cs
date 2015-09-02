// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Net.Security;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Secur32
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct SSPIHandle
        {
            private IntPtr HandleHi;
            private IntPtr HandleLo;
    
            public bool IsZero
            {
                get { return HandleHi == IntPtr.Zero && HandleLo1 == IntPtr.Zero; }
            }

            public IntPtr HandleLo1
            {
                get
                {
                    return HandleLo;
                }

                set
                {
                    HandleLo = value;
                }
            }

            internal void SetToInvalid()
            {
                HandleHi = IntPtr.Zero;
                HandleLo1 = IntPtr.Zero;
            }
    
            public override string ToString()
            {
                { return HandleHi.ToString("x") + ":" + HandleLo1.ToString("x"); }
            }
        }

        internal enum ContextAttribute
        {
            //
            // look into <sspi.h> and <schannel.h>
            //
            Sizes = 0x00,
            Names = 0x01,
            Lifespan = 0x02,
            DceInfo = 0x03,
            StreamSizes = 0x04,
            //KeyInfo             = 0x05, must not be used, see ConnectionInfo instead
            Authority = 0x06,
            // SECPKG_ATTR_PROTO_INFO          = 7,
            // SECPKG_ATTR_PASSWORD_EXPIRY     = 8,
            // SECPKG_ATTR_SESSION_KEY         = 9,
            PackageInfo = 0x0A,
            // SECPKG_ATTR_USER_FLAGS          = 11,
            NegotiationInfo = 0x0C,
            // SECPKG_ATTR_NATIVE_NAMES        = 13,
            // SECPKG_ATTR_FLAGS               = 14,
            // SECPKG_ATTR_USE_VALIDATED       = 15,
            // SECPKG_ATTR_CREDENTIAL_NAME     = 16,
            // SECPKG_ATTR_TARGET_INFORMATION  = 17,
            // SECPKG_ATTR_ACCESS_TOKEN        = 18,
            // SECPKG_ATTR_TARGET              = 19,
            // SECPKG_ATTR_AUTHENTICATION_ID   = 20,
            UniqueBindings = 0x19,
            EndpointBindings = 0x1A,
            ClientSpecifiedSpn = 0x1B, // SECPKG_ATTR_CLIENT_SPECIFIED_TARGET = 27
            RemoteCertificate = 0x53,
            LocalCertificate = 0x54,
            RootStore = 0x55,
            IssuerListInfoEx = 0x59,
            ConnectionInfo = 0x5A,
            // SECPKG_ATTR_EAP_KEY_BLOCK        0x5b   // returns SecPkgContext_EapKeyBlock  
            // SECPKG_ATTR_MAPPED_CRED_ATTR     0x5c   // returns SecPkgContext_MappedCredAttr  
            // SECPKG_ATTR_SESSION_INFO         0x5d   // returns SecPkgContext_SessionInfo  
            // SECPKG_ATTR_APP_DATA             0x5e   // sets/returns SecPkgContext_SessionAppData  
            // SECPKG_ATTR_REMOTE_CERTIFICATES  0x5F   // returns SecPkgContext_Certificates  
            // SECPKG_ATTR_CLIENT_CERT_POLICY   0x60   // sets    SecPkgCred_ClientCertCtlPolicy  
            // SECPKG_ATTR_CC_POLICY_RESULT     0x61   // returns SecPkgContext_ClientCertPolicyResult  
            // SECPKG_ATTR_USE_NCRYPT           0x62   // Sets the CRED_FLAG_USE_NCRYPT_PROVIDER FLAG on cred group  
            // SECPKG_ATTR_LOCAL_CERT_INFO      0x63   // returns SecPkgContext_CertInfo  
            // SECPKG_ATTR_CIPHER_INFO          0x64   // returns new CNG SecPkgContext_CipherInfo  
            // SECPKG_ATTR_EAP_PRF_INFO         0x65   // sets    SecPkgContext_EapPrfInfo  
            // SECPKG_ATTR_SUPPORTED_SIGNATURES 0x66   // returns SecPkgContext_SupportedSignatures  
            // SECPKG_ATTR_REMOTE_CERT_CHAIN    0x67   // returns PCCERT_CONTEXT  
            UiInfo = 0x68, // sets SEcPkgContext_UiInfo  
        }

        internal enum Endianness
        {
            Network = 0x00,
            Native = 0x10,
        }

        internal enum CredentialUse
        {
            Inbound = 0x1,
            Outbound = 0x2,
            Both = 0x3,
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct _CERT_CHAIN_ELEMENT
        {
            public uint cbSize;
            public IntPtr pCertContext;
            // Since this structure is allocated by unmanaged code, we can
            // omit the fileds below since we don't need to access them
            // CERT_TRUST_STATUS   TrustStatus;
            // IntPtr                pRevocationInfo;
            // IntPtr                pIssuanceUsage;
            // IntPtr                pApplicationUsage;
        }

        // CRYPTOAPI_BLOB
        //[StructLayout(LayoutKind.Sequential)]
        //unsafe struct CryptoBlob {
        //    // public uint cbData;
        //    // public byte* pbData;
        //    public uint dataSize;
        //    public byte* dataBlob;
        //}

        // SecPkgContext_IssuerListInfoEx
        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct IssuerListInfoEx
        {
            public SafeHandle aIssuers;
            public uint cIssuers;

            public unsafe IssuerListInfoEx(SafeHandle handle, byte[] nativeBuffer)
            {
                aIssuers = handle;
                fixed (byte* voidPtr = nativeBuffer)
                {
                    // if this breaks on 64 bit, do the sizeof(IntPtr) trick
                    cIssuers = *((uint*)(voidPtr + IntPtr.Size));
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SecureCredential
        {
            /*
            typedef struct _SCHANNEL_CRED
            {
                DWORD           dwVersion;      // always SCHANNEL_CRED_VERSION
                DWORD           cCreds;
                PCCERT_CONTEXT *paCred;
                HCERTSTORE      hRootStore;

                DWORD           cMappers;
                struct _HMAPPER **aphMappers;

                DWORD           cSupportedAlgs;
                ALG_ID *        palgSupportedAlgs;

                DWORD           grbitEnabledProtocols;
                DWORD           dwMinimumCipherStrength;
                DWORD           dwMaximumCipherStrength;
                DWORD           dwSessionLifespan;
                DWORD           dwFlags;
                DWORD           reserved;
            } SCHANNEL_CRED, *PSCHANNEL_CRED;
            */

            public const int CurrentVersion = 0x4;

            public int version;
            public int cCreds;

            // ptr to an array of pointers
            // There is a hack done with this field.  AcquireCredentialsHandle requires an array of
            // certificate handles; we only ever use one.  In order to avoid pinning a one element array,
            // we copy this value onto the stack, create a pointer on the stack to the copied value,
            // and replace this field with the pointer, during the call to AcquireCredentialsHandle.
            // Then we fix it up afterwards.  Fine as long as all the SSPI credentials are not
            // supposed to be threadsafe.
            public IntPtr certContextArray;

            public IntPtr rootStore;               // == always null, OTHERWISE NOT RELIABLE
            public int cMappers;
            public IntPtr phMappers;               // == always null, OTHERWISE NOT RELIABLE
            public int cSupportedAlgs;
            public IntPtr palgSupportedAlgs;       // == always null, OTHERWISE NOT RELIABLE
            public int grbitEnabledProtocols;
            public int dwMinimumCipherStrength;
            public int dwMaximumCipherStrength;
            public int dwSessionLifespan;
            public SecureCredential.Flags dwFlags;
            public int reserved;

            [Flags]
            public enum Flags
            {
                Zero = 0,
                NoSystemMapper = 0x02,
                NoNameCheck = 0x04,
                ValidateManual = 0x08,
                NoDefaultCred = 0x10,
                ValidateAuto = 0x20,
                UseStrongCrypto = 0x00400000,
            }
        } // SecureCredential

        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct SecurityBufferStruct
        {
            public int count;
            public BufferType type;
            public IntPtr token;

            public static readonly int Size = sizeof(SecurityBufferStruct);
        }

        [StructLayout(LayoutKind.Sequential)]
        internal unsafe class SecurityBufferDescriptor
        {
            /*
            typedef struct _SecBufferDesc {
                ULONG        ulVersion;
                ULONG        cBuffers;
                PSecBuffer   pBuffers;
            } SecBufferDesc, * PSecBufferDesc;
            */
            public readonly int Version;
            public readonly int Count;
            public void* UnmanagedPointer;

            public SecurityBufferDescriptor(int count)
            {
                Version = 0;
                Count = count;
                UnmanagedPointer = null;
            }
        } // SecurityBufferDescriptor

        [DllImport(Interop.Libraries.Secur32, ExactSpelling = true, SetLastError = true)]
        internal static extern int EncryptMessage(
              ref SSPIHandle contextHandle,
              [In] uint qualityOfProtection,
              [In, Out] SecurityBufferDescriptor inputOutput,
              [In] uint sequenceNumber
              );

        [DllImport(Interop.Libraries.Secur32, ExactSpelling = true, SetLastError = true)]
        internal static unsafe extern int DecryptMessage(
              [In] ref SSPIHandle contextHandle,
              [In, Out] SecurityBufferDescriptor inputOutput,
              [In] uint sequenceNumber,
                   uint* qualityOfProtection
              );

        [DllImport(Interop.Libraries.Secur32, ExactSpelling = true, SetLastError = true)]
        internal static extern int QuerySecurityContextToken(
            ref SSPIHandle phContext,
            [Out] out SecurityContextTokenHandle handle);

        [DllImport(Interop.Libraries.Secur32, ExactSpelling = true, SetLastError = true)]
        internal static extern int FreeContextBuffer(
            [In] IntPtr contextBuffer);

        [DllImport(Interop.Libraries.Secur32, ExactSpelling = true, SetLastError = true)]
        internal static extern int FreeCredentialsHandle(
              ref SSPIHandle handlePtr
              );

        [DllImport(Interop.Libraries.Secur32, ExactSpelling = true, SetLastError = true)]
        internal static extern int DeleteSecurityContext(
              ref SSPIHandle handlePtr
              );

        [DllImport(Interop.Libraries.Secur32, ExactSpelling = true, SetLastError = true)]
        internal unsafe static extern int AcceptSecurityContext(
                  ref SSPIHandle credentialHandle,
                  [In] void* inContextPtr,
                  [In] SecurityBufferDescriptor inputBuffer,
                  [In] ContextFlags inFlags,
                  [In] Endianness endianness,
                  ref SSPIHandle outContextPtr,
                  [In, Out] SecurityBufferDescriptor outputBuffer,
                  [In, Out] ref ContextFlags attributes,
                  out long timeStamp
                  );

        [DllImport(Interop.Libraries.Secur32, ExactSpelling = true, SetLastError = true)]
        internal unsafe static extern int QueryContextAttributesW(
            ref SSPIHandle contextHandle,
            [In] ContextAttribute attribute,
            [In] void* buffer);

        [DllImport(Interop.Libraries.Secur32, ExactSpelling = true, SetLastError = true)]
        internal unsafe static extern int SetContextAttributesW(
            ref SSPIHandle contextHandle,
            [In] ContextAttribute attribute,
            [In] byte[] buffer,
            [In] int bufferSize);

        [DllImport(Interop.Libraries.Secur32, ExactSpelling = true, SetLastError = true)]
        internal static extern int EnumerateSecurityPackagesW(
            [Out] out int pkgnum,
            [Out] out SafeFreeContextBuffer_SECURITY handle);

        [DllImport(Interop.Libraries.Secur32, ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        internal unsafe static extern int AcquireCredentialsHandleW(
                  [In] string principal,
                  [In] string moduleName,
                  [In] int usage,
                  [In] void* logonID,
                  [In] ref AuthIdentity authdata,
                  [In] void* keyCallback,
                  [In] void* keyArgument,
                  ref SSPIHandle handlePtr,
                  [Out] out long timeStamp
                  );

        [DllImport(Interop.Libraries.Secur32, ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        internal unsafe static extern int AcquireCredentialsHandleW(
                  [In] string principal,
                  [In] string moduleName,
                  [In] int usage,
                  [In] void* logonID,
                  [In] IntPtr zero,
                  [In] void* keyCallback,
                  [In] void* keyArgument,
                  ref SSPIHandle handlePtr,
                  [Out] out long timeStamp
                  );

        [DllImport(Interop.Libraries.Secur32, ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        internal unsafe static extern int AcquireCredentialsHandleW(
                  [In] string principal,
                  [In] string moduleName,
                  [In] int usage,
                  [In] void* logonID,
                  [In] SafeSspiAuthDataHandle authdata,
                  [In] void* keyCallback,
                  [In] void* keyArgument,
                  ref SSPIHandle handlePtr,
                  [Out] out long timeStamp
                  );

        [DllImport(Interop.Libraries.Secur32, ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        internal unsafe static extern int AcquireCredentialsHandleW(
                  [In] string principal,
                  [In] string moduleName,
                  [In] int usage,
                  [In] void* logonID,
                  [In] ref SecureCredential authData,
                  [In] void* keyCallback,
                  [In] void* keyArgument,
                  ref SSPIHandle handlePtr,
                  [Out] out long timeStamp
                  );

        [DllImport(Interop.Libraries.Secur32, ExactSpelling = true, SetLastError = true)]
        internal unsafe static extern int InitializeSecurityContextW(
                  ref SSPIHandle credentialHandle,
                  [In] void* inContextPtr,
                  [In] byte* targetName,
                  [In] ContextFlags inFlags,
                  [In] int reservedI,
                  [In] Endianness endianness,
                  [In] SecurityBufferDescriptor inputBuffer,
                  [In] int reservedII,
                  ref SSPIHandle outContextPtr,
                  [In, Out] SecurityBufferDescriptor outputBuffer,
                  [In, Out] ref ContextFlags attributes,
                  out long timeStamp
                  );

        [DllImport(Interop.Libraries.Secur32, ExactSpelling = true, SetLastError = true)]
        internal unsafe static extern int CompleteAuthToken(
                  [In] void* inContextPtr,
                  [In, Out] SecurityBufferDescriptor inputBuffers
                  );

        [DllImport(Interop.Libraries.Secur32, ExactSpelling = true, SetLastError = true)]
        internal unsafe static extern SecurityStatus SspiFreeAuthIdentity(
            [In] IntPtr authData);
    }
}
