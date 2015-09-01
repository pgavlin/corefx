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
