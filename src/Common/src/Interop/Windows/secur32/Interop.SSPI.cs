// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
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
    }
}
