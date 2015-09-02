// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
/*++
Copyright (c) Microsoft Corporation

Module Name:

    _SafeNetHandles.cs

Abstract:
        The file contains _all_ SafeHandles implementations for System.Net namespace.
        These handle wrappers do guarantee that OS resources get cleaned up when the app domain dies.

        All PInvoke declarations that do freeing  the  OS resources  _must_ be in this file
        All PInvoke declarations that do allocation the OS resources _must_ be in this file


Details:

        The protection from leaking OF the OS resources is based on two technologies
        1) SafeHandle class
        2) Non interuptible regions using Constrained Execution Region (CER) technology

        For simple cases SafeHandle class does all the job. The Prerequisites are:
        - A resource is able to be represented by IntPtr type (32 bits on 32 bits platforms).
        - There is a PInvoke availble that does the creation of the resource.
          That PInvoke either returns the handle value or it writes the handle into out/ref parameter.
        - The above PInvoke as part of the call does NOT free any OS resource.

        For those "simple" cases we desinged SafeHandle-derived classes that provide
        static methods to allocate a handle object.
        Each such derived class provides a handle release method that is run as non-interrupted.

        For more complicated cases we employ the support for non-interruptible methods (CERs).
        Each CER is a tree of code rooted at a catch or finally clause for a specially marked exception
        handler (preceded by the RuntimeHelpers.PrepareConstrainedRegions() marker) or the Dispose or
        ReleaseHandle method of a SafeHandle derived class. The graph is automatically computed by the
        runtime (typically at the jit time of the root method), but cannot follow virtual or interface
        calls (these must be explicitly prepared via RuntimeHelpers.PrepareMethod once the definite target
        method is known). Also, methods in the graph that must be included in the CER must be marked with
        a reliability contract stating guarantees about the consistency of the system if an error occurs
        while they are executing. Look for ReliabilityContract for examples (a full explanation of the
        semantics of this contract is beyond the scope of this comment).

        An example of the top-level of a CER:

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                // Normal code
            }
            finally
            {
                // Guaranteed to get here even in low memory scenarios. Thread abort will not interrupt
                // this clause and we won't fail because of a jit allocation of any method called (modulo
                // restrictions on interface/virtual calls listed above and further restrictions listed
                // below).
            }

        Another common pattern is an empty-try (where you really just want a region of code the runtime
        won't interrupt you in):

            RuntimeHelpers.PrepareConstrainedRegions();
            try {} finally
            {
                // Non-interruptible code here
            }

        This ugly syntax will be supplanted with compiler support at some point.

        While within a CER region certain restrictions apply in order to avoid having the runtime inject
        a potential fault point into your code (and of course you're are responsible for ensuring your
        code doesn't inject any explicit fault points of its own unless you know how to tolerate them).

        A quick and dirty guide to the possible causes of fault points in CER regions:
        - Explicit allocations (though allocating a value type only implies allocation on the stack,
          which may not present an issue).
        - Boxing a value type (C# does this implicitly for you in many cases, so be careful).
        - Use of Monitor.Enter or the lock keyword.
        - Accessing a multi-dimensional array.
        - Calling any method outside your control that doesn't make a guarantee (e.g. via a
          ReliabilityAttribute) that it doesn't introduce failure points.
        - Making P/Invoke calls with non-blittable parameters types. Blittable types are:
            - SafeHandle when used as an [in] parameter
            - NON BOXED base types that fit onto a machine word
            - ref struct with blittable fields
            - class type with blittable fields
            - pinned Unicode strings using "fixed" statement
            - pointers of any kind
            - IntPtr type
        - P/Invokes should not have any CharSet attribute on it's declaration.
          Obvioulsy string types should not appear in the parameters.
        - String type MUST not appear in a field of a marshaled ref struct or class in a P?Invoke

Author:

    Alexei Vopilov    04-Sept-2002

Revision History:

--*/

using System.Net;
using System.Security;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Security.Authentication.ExtendedProtection;
using System.ComponentModel;
using System.Text;
using System.Globalization;
using Microsoft.Win32.SafeHandles;
using System.Diagnostics.CodeAnalysis;
using System.Collections.Generic;

namespace System.Net.Security
{
    //
    // Used when working with SSPI APIs, like SafeSspiAuthDataHandle(). Holds the pointer to the auth. data blob.
    //
#if DEBUG
    internal sealed class SafeSspiAuthDataHandle : DebugSafeHandle
    {
#else
    internal sealed class SafeSspiAuthDataHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
#endif
        public SafeSspiAuthDataHandle() : base(true)
        {
        }

        protected override bool ReleaseHandle()
        {
            return Interop.Secur32.SspiFreeAuthIdentity(handle) == Interop.SecurityStatus.OK;
        }
    }

    ///////////////////////////////////////////////////////////////
    //
    //  A set of Safe Handles that depend on native FreeContextBuffer finalizer
    //
    ///////////////////////////////////////////////////////////////

#if DEBUG
    internal abstract class SafeFreeContextBuffer : DebugSafeHandle
    {
#else
    internal abstract class SafeFreeContextBuffer : SafeHandleZeroOrMinusOneIsInvalid
    {
#endif
        protected SafeFreeContextBuffer() : base(true) { }

        // This must be ONLY called from this file and in the context of a CER
        internal unsafe void Set(IntPtr value)
        {
            this.handle = value;
        }

        //
        //
        internal static int EnumeratePackages(out int pkgnum, out SafeFreeContextBuffer pkgArray)
        {
            int res = -1;
            SafeFreeContextBuffer_SECURITY pkgArray_SECURITY = null;
            res = Interop.Secur32.EnumerateSecurityPackagesW(out pkgnum, out pkgArray_SECURITY);
            pkgArray = pkgArray_SECURITY;

            if (res != 0 && pkgArray != null)
            {
                pkgArray.SetHandleAsInvalid();
            }

            return res;
        }

        //
        //
        internal static SafeFreeContextBuffer CreateEmptyHandle()
        {
            return new SafeFreeContextBuffer_SECURITY();
        }

        //
        // After PINvoke call the method will fix the refHandle.handle with the returned value.
        // The caller is responsible for creating a correct SafeHandle template or null can be passed if no handle is returned.
        //
        // This method switches between three non-interruptible helper methods.  (This method can't be both non-interruptible and
        // reference imports from all three DLLs - doing so would cause all three DLLs to try to be bound to.)
        //
        public unsafe static int QueryContextAttributes(SafeDeleteContext phContext, Interop.Secur32.ContextAttribute contextAttribute, byte* buffer, SafeHandle refHandle)
        {
            return QueryContextAttributes_SECURITY(phContext, contextAttribute, buffer, refHandle);
        }

        private unsafe static int QueryContextAttributes_SECURITY(
            SafeDeleteContext phContext,
            Interop.Secur32.ContextAttribute contextAttribute,
            byte* buffer,
            SafeHandle refHandle)
        {
            int status = (int)Interop.SecurityStatus.InvalidHandle;
            bool b = false;

            // We don't want to be interrupted by thread abort exceptions or unexpected out-of-memory errors failing to jit
            // one of the following methods. So run within a CER non-interruptible block.
            try
            {
                phContext.DangerousAddRef(ref b);
            }
            catch (Exception e)
            {
                if (b)
                {
                    phContext.DangerousRelease();
                    b = false;
                }
                if (!(e is ObjectDisposedException))
                    throw;
            }
            finally
            {
                if (b)
                {
                    status = Interop.Secur32.QueryContextAttributesW(ref phContext._handle, contextAttribute, buffer);
                    phContext.DangerousRelease();
                }

                if (status == 0 && refHandle != null)
                {
                    if (refHandle is SafeFreeContextBuffer)
                    {
                        ((SafeFreeContextBuffer)refHandle).Set(*(IntPtr*)buffer);
                    }
                    else
                    {
                        ((SafeFreeCertContext)refHandle).Set(*(IntPtr*)buffer);
                    }
                }

                if (status != 0 && refHandle != null)
                {
                    refHandle.SetHandleAsInvalid();
                }
            }

            return status;
        }

        public static int SetContextAttributes(SafeDeleteContext phContext,
            Interop.Secur32.ContextAttribute contextAttribute, byte[] buffer)
        {
            return SetContextAttributes_SECURITY(phContext, contextAttribute, buffer);
        }

        private static int SetContextAttributes_SECURITY(
            SafeDeleteContext phContext,
            Interop.Secur32.ContextAttribute contextAttribute,
            byte[] buffer)
        {
            int status = (int)Interop.SecurityStatus.InvalidHandle;
            bool b = false;

            // We don't want to be interrupted by thread abort exceptions or unexpected out-of-memory errors failing 
            // to jit one of the following methods. So run within a CER non-interruptible block.
            try
            {
                phContext.DangerousAddRef(ref b);
            }
            catch (Exception e)
            {
                if (b)
                {
                    phContext.DangerousRelease();
                    b = false;
                }
                if (!(e is ObjectDisposedException))
                    throw;
            }
            finally
            {
                if (b)
                {
                    status = Interop.Secur32.SetContextAttributesW(
                        ref phContext._handle, contextAttribute, buffer, buffer.Length);
                    phContext.DangerousRelease();
                }
            }

            return status;
        }
    }

    //=======================================================
    internal sealed class SafeFreeContextBuffer_SECURITY : SafeFreeContextBuffer
    {
        internal SafeFreeContextBuffer_SECURITY() : base() { }

        override protected bool ReleaseHandle()
        {
            return Interop.Secur32.FreeContextBuffer(handle) == 0;
        }
    }
    //=======================================================

    ///////////////////////////////////////////////////////////////
    //
    // Implementation of handles required CertFreeCertificateContext
    //
    ///////////////////////////////////////////////////////////////
#if DEBUG
    internal sealed class SafeFreeCertContext : DebugSafeHandle
    {
#else
    internal sealed class SafeFreeCertContext : SafeHandleZeroOrMinusOneIsInvalid
    {
#endif

        internal SafeFreeCertContext() : base(true) { }

        // This must be ONLY called from this file within a CER.
        internal unsafe void Set(IntPtr value)
        {
            this.handle = value;
        }

        const uint CRYPT_ACQUIRE_SILENT_FLAG = 0x00000040;

        override protected bool ReleaseHandle()
        {
            Interop.Crypt32.CertFreeCertificateContext(handle);
            return true;
        }
    }

    ///////////////////////////////////////////////////////////////
    //
    // Implementation of handles dependable on FreeCredentialsHandle
    //
    //
    ///////////////////////////////////////////////////////////////
    //------------------------------------------------------------
#if DEBUG
    internal abstract class SafeFreeCredentials : DebugSafeHandle
    {
#else
    internal abstract class SafeFreeCredentials : SafeHandle
    {
#endif

        internal Interop.Secur32.SSPIHandle _handle;    //should be always used as by ref in PINvokes parameters

        protected SafeFreeCredentials() : base(IntPtr.Zero, true)
        {
            _handle = new Interop.Secur32.SSPIHandle();
        }

#if TRAVE
        public override string ToString()
        {
            return "0x" + _handle.ToString();
        }
#endif

        public override bool IsInvalid
        {
            get { return IsClosed || _handle.IsZero; }
        }

#if DEBUG
        //This method should never be called for this type
        public new IntPtr DangerousGetHandle()
        {
            throw new InvalidOperationException();
        }
#endif

        public unsafe static int AcquireCredentialsHandle(
                                                    string package,
                                                    Interop.Secur32.CredentialUse intent,
                                                    ref Interop.Secur32.AuthIdentity authdata,
                                                    out SafeFreeCredentials outCredential
                                                    )
        {
            GlobalLog.Print("SafeFreeCredentials::AcquireCredentialsHandle#1("
                            + package + ", "
                            + intent + ", "
                            + authdata + ")"
                            );

            int errorCode = -1;
            long timeStamp;

            outCredential = new SafeFreeCredential_SECURITY();

            errorCode = Interop.Secur32.AcquireCredentialsHandleW(
                                                    null,
                                                    package,
                                                    (int)intent,
                                                    null,
                                                    ref authdata,
                                                    null,
                                                    null,
                                                    ref outCredential._handle,
                                                    out timeStamp
                                                    );
#if TRAVE
            GlobalLog.Print("Unmanaged::AcquireCredentialsHandle() returns 0x"
                            + String.Format("{0:x}", errorCode)
                            + ", handle = " + outCredential.ToString()
                            );
#endif

            if (errorCode != 0)
            {
                outCredential.SetHandleAsInvalid();
            }
            return errorCode;
        }

        public unsafe static int AcquireDefaultCredential(
                                                    string package,
                                                    Interop.Secur32.CredentialUse intent,
                                                    out SafeFreeCredentials outCredential
                                                    )
        {
            GlobalLog.Print("SafeFreeCredentials::AcquireDefaultCredential("
                            + package + ", "
                            + intent + ")"
                            );

            int errorCode = -1;
            long timeStamp;

            outCredential = new SafeFreeCredential_SECURITY();

            errorCode = Interop.Secur32.AcquireCredentialsHandleW(
                                                null,
                                                package,
                                                (int)intent,
                                                null,
                                                IntPtr.Zero,
                                                null,
                                                null,
                                                ref outCredential._handle,
                                                out timeStamp
                                                );

#if TRAVE
            GlobalLog.Print("Unmanaged::AcquireCredentialsHandle() returns 0x"
                            + errorCode.ToString("x")
                            + ", handle = " + outCredential.ToString()
                            );
#endif

            if (errorCode != 0)
            {
                outCredential.SetHandleAsInvalid();
            }
            return errorCode;
        }

        // This overload is only called on Win7+ where SspiEncodeStringsAsAuthIdentity() was used to
        // create the authData blob.
        public unsafe static int AcquireCredentialsHandle(
                                                    string package,
                                                    Interop.Secur32.CredentialUse intent,
                                                    ref SafeSspiAuthDataHandle authdata,
                                                    out SafeFreeCredentials outCredential
                                                    )
        {
            int errorCode = -1;
            long timeStamp;

            outCredential = new SafeFreeCredential_SECURITY();
            errorCode = Interop.Secur32.AcquireCredentialsHandleW(
                                                    null,
                                                    package,
                                                    (int)intent,
                                                    null,
                                                    authdata,
                                                    null,
                                                    null,
                                                    ref outCredential._handle,
                                                    out timeStamp
                                                    );

            if (errorCode != 0)
            {
                outCredential.SetHandleAsInvalid();
            }
            return errorCode;
        }

        public unsafe static int AcquireCredentialsHandle(
                                                    string package,
                                                    Interop.Secur32.CredentialUse intent,
                                                    ref Interop.Secur32.SecureCredential authdata,
                                                    out SafeFreeCredentials outCredential
                                                    )
        {
            GlobalLog.Print("SafeFreeCredentials::AcquireCredentialsHandle#2("
                            + package + ", "
                            + intent + ", "
                            + authdata + ")"
                            );

            int errorCode = -1;
            long timeStamp;


            // If there is a certificate, wrap it into an array.
            // Not threadsafe.
            IntPtr copiedPtr = authdata.certContextArray;
            try
            {
                IntPtr certArrayPtr = new IntPtr(&copiedPtr);
                if (copiedPtr != IntPtr.Zero)
                {
                    authdata.certContextArray = certArrayPtr;
                }

                outCredential = new SafeFreeCredential_SECURITY();

                errorCode = Interop.Secur32.AcquireCredentialsHandleW(
                                                    null,
                                                    package,
                                                    (int)intent,
                                                    null,
                                                    ref authdata,
                                                    null,
                                                    null,
                                                    ref outCredential._handle,
                                                    out timeStamp
                                                    );
            }
            finally
            {
                authdata.certContextArray = copiedPtr;
            }

#if TRAVE
            GlobalLog.Print("Unmanaged::AcquireCredentialsHandle() returns 0x"
                            + errorCode.ToString("x")
                            + ", handle = " + outCredential.ToString()
                            );
#endif

            if (errorCode != 0)
            {
                outCredential.SetHandleAsInvalid();
            }
            return errorCode;
        }
    }
    //
    // This is a class holding a Credential handle reference, used for static handles cache
    //
#if DEBUG
    internal sealed class SafeCredentialReference : DebugCriticalHandleMinusOneIsInvalid
    {
#else
    internal sealed class SafeCredentialReference : CriticalHandleMinusOneIsInvalid
    {
#endif

        //
        // Static cache will return the target handle if found the reference in the table.
        //
        internal SafeFreeCredentials _Target;

        //
        //
        internal static SafeCredentialReference CreateReference(SafeFreeCredentials target)
        {
            SafeCredentialReference result = new SafeCredentialReference(target);
            if (result.IsInvalid)
                return null;

            return result;
        }
        private SafeCredentialReference(SafeFreeCredentials target) : base()
        {
            // Bumps up the refcount on Target to signify that target handle is statically cached so
            // its dispose should be postponed
            bool b = false;
            try
            {
                target.DangerousAddRef(ref b);
            }
            catch
            {
                if (b)
                {
                    target.DangerousRelease();
                    b = false;
                }
            }
            finally
            {
                if (b)
                {
                    _Target = target;
                    SetHandle(new IntPtr(0));   // make this handle valid
                }
            }
        }

        override protected bool ReleaseHandle()
        {
            SafeFreeCredentials target = _Target;
            if (target != null)
                target.DangerousRelease();
            _Target = null;
            return true;
        }
    }

    //======================================================================
    internal sealed class SafeFreeCredential_SECURITY : SafeFreeCredentials
    {
        public SafeFreeCredential_SECURITY() : base() { }

        override protected bool ReleaseHandle()
        {
            return Interop.Secur32.FreeCredentialsHandle(ref _handle) == 0;
        }
    }
    //======================================================================

    ///////////////////////////////////////////////////////////////
    //
    // Implementation of handles that are dependent on DeleteSecurityContext
    //
    //
    ///////////////////////////////////////////////////////////////
#if DEBUG
    internal abstract class SafeDeleteContext : DebugSafeHandle
    {
#else
    internal abstract class SafeDeleteContext : SafeHandle
    {
#endif
        private const string dummyStr = " ";
        private static readonly byte[] dummyBytes = new byte[] { 0 };

        //
        // ATN: _handle is internal since it is used on PInvokes by other wrapper methods.
        //      However all such wrappers MUST manually and reliably adjust refCounter of SafeDeleteContext handle.
        //
        internal Interop.Secur32.SSPIHandle _handle;

        protected SafeFreeCredentials _EffectiveCredential;

        protected SafeDeleteContext() : base(IntPtr.Zero, true)
        {
            _handle = new Interop.Secur32.SSPIHandle();
        }

        public override bool IsInvalid
        {
            get
            {
                return IsClosed || _handle.IsZero;
            }
        }

        public override string ToString()
        {
            return _handle.ToString();
        }

#if DEBUG
        //This method should never be called for this type
        public new IntPtr DangerousGetHandle()
        {
            throw new InvalidOperationException();
        }
#endif

        //-------------------------------------------------------------------
        internal unsafe static int InitializeSecurityContext(
                                                    ref SafeFreeCredentials inCredentials,
                                                    ref SafeDeleteContext refContext,
                                                    string targetName,
                                                    Interop.Secur32.ContextFlags inFlags,
                                                    Interop.Secur32.Endianness endianness,
                                                    SecurityBuffer inSecBuffer,
                                                    SecurityBuffer[] inSecBuffers,
                                                    SecurityBuffer outSecBuffer,
                                                    ref Interop.Secur32.ContextFlags outFlags)
        {
#if TRAVE
            GlobalLog.Enter("SafeDeleteContext::InitializeSecurityContext");
            GlobalLog.Print("    credential       = " + inCredentials.ToString());
            GlobalLog.Print("    refContext       = " + Logging.ObjectToString(refContext));
            GlobalLog.Print("    targetName       = " + targetName);
            GlobalLog.Print("    inFlags          = " + inFlags);
            GlobalLog.Print("    reservedI        = 0x0");
            GlobalLog.Print("    endianness       = " + endianness);

            if (inSecBuffers == null)
            {
                GlobalLog.Print("    inSecBuffers     = (null)");
            }
            else
            {
                GlobalLog.Print("    inSecBuffers[]   = length:" + inSecBuffers.Length);
            }
#endif
            GlobalLog.Assert(outSecBuffer != null, "SafeDeleteContext::InitializeSecurityContext()|outSecBuffer != null");
            GlobalLog.Assert(inSecBuffer == null || inSecBuffers == null, "SafeDeleteContext::InitializeSecurityContext()|inSecBuffer == null || inSecBuffers == null");

            if (inCredentials == null)
            {
                throw new ArgumentNullException("inCredentials");
            }

            Interop.Secur32.SecurityBufferDescriptor inSecurityBufferDescriptor = null;
            if (inSecBuffer != null)
            {
                inSecurityBufferDescriptor = new Interop.Secur32.SecurityBufferDescriptor(1);
            }
            else if (inSecBuffers != null)
            {
                inSecurityBufferDescriptor = new Interop.Secur32.SecurityBufferDescriptor(inSecBuffers.Length);
            }
            Interop.Secur32.SecurityBufferDescriptor outSecurityBufferDescriptor = new Interop.Secur32.SecurityBufferDescriptor(1);

            // actually this is returned in outFlags
            bool isSspiAllocated = (inFlags & Interop.Secur32.ContextFlags.AllocateMemory) != 0 ? true : false;

            int errorCode = -1;

            Interop.Secur32.SSPIHandle contextHandle = new Interop.Secur32.SSPIHandle();
            if (refContext != null)
                contextHandle = refContext._handle;

            // these are pinned user byte arrays passed along with SecurityBuffers
            GCHandle[] pinnedInBytes = null;
            GCHandle pinnedOutBytes = new GCHandle();
            // optional output buffer that may need to be freed
            SafeFreeContextBuffer outFreeContextBuffer = null;
            try
            {
                pinnedOutBytes = GCHandle.Alloc(outSecBuffer.token, GCHandleType.Pinned);
                Interop.Secur32.SecurityBufferStruct[] inUnmanagedBuffer = new Interop.Secur32.SecurityBufferStruct[inSecurityBufferDescriptor == null ? 1 : inSecurityBufferDescriptor.Count];
                fixed (void* inUnmanagedBufferPtr = inUnmanagedBuffer)
                {
                    if (inSecurityBufferDescriptor != null)
                    {
                        // Fix Descriptor pointer that points to unmanaged SecurityBuffers
                        inSecurityBufferDescriptor.UnmanagedPointer = inUnmanagedBufferPtr;
                        pinnedInBytes = new GCHandle[inSecurityBufferDescriptor.Count];
                        SecurityBuffer securityBuffer;
                        for (int index = 0; index < inSecurityBufferDescriptor.Count; ++index)
                        {
                            securityBuffer = inSecBuffer != null ? inSecBuffer : inSecBuffers[index];
                            if (securityBuffer != null)
                            {
                                // Copy the SecurityBuffer content into unmanaged place holder
                                inUnmanagedBuffer[index].count = securityBuffer.size;
                                inUnmanagedBuffer[index].type = securityBuffer.type;

                                // use the unmanaged token if it's not null; otherwise use the managed buffer
                                if (securityBuffer.unmanagedToken != null)
                                {
                                    inUnmanagedBuffer[index].token = securityBuffer.unmanagedToken.DangerousGetHandle();
                                }
                                else if (securityBuffer.token == null || securityBuffer.token.Length == 0)
                                {
                                    inUnmanagedBuffer[index].token = IntPtr.Zero;
                                }
                                else
                                {
                                    pinnedInBytes[index] = GCHandle.Alloc(securityBuffer.token, GCHandleType.Pinned);
                                    inUnmanagedBuffer[index].token = Marshal.UnsafeAddrOfPinnedArrayElement(securityBuffer.token, securityBuffer.offset);
                                }
#if TRAVE
                                GlobalLog.Print("SecBuffer: cbBuffer:" + securityBuffer.size + " BufferType:" + securityBuffer.type);
#endif
                            }
                        }
                    }

                    Interop.Secur32.SecurityBufferStruct[] outUnmanagedBuffer = new Interop.Secur32.SecurityBufferStruct[1];
                    fixed (void* outUnmanagedBufferPtr = outUnmanagedBuffer)
                    {
                        // Fix Descriptor pointer that points to unmanaged SecurityBuffers
                        outSecurityBufferDescriptor.UnmanagedPointer = outUnmanagedBufferPtr;
                        outUnmanagedBuffer[0].count = outSecBuffer.size;
                        outUnmanagedBuffer[0].type = outSecBuffer.type;
                        if (outSecBuffer.token == null || outSecBuffer.token.Length == 0)
                            outUnmanagedBuffer[0].token = IntPtr.Zero;
                        else
                            outUnmanagedBuffer[0].token = Marshal.UnsafeAddrOfPinnedArrayElement(outSecBuffer.token, outSecBuffer.offset);

                        if (isSspiAllocated)
                        {
                            outFreeContextBuffer = SafeFreeContextBuffer.CreateEmptyHandle();
                        }

                        if (refContext == null || refContext.IsInvalid)
                            refContext = new SafeDeleteContext_SECURITY();

                        if (targetName == null || targetName.Length == 0)
                            targetName = dummyStr;

                        fixed (char* namePtr = targetName)
                        {
                            errorCode = MustRunInitializeSecurityContext_SECURITY(
                                            ref inCredentials,
                                            contextHandle.IsZero ? null : &contextHandle,
                                            (byte*)(((object)targetName == (object)dummyStr) ? null : namePtr),
                                            inFlags,
                                            endianness,
                                            inSecurityBufferDescriptor,
                                            refContext,
                                            outSecurityBufferDescriptor,
                                            ref outFlags,
                                            outFreeContextBuffer
                                            );
                        }

                        GlobalLog.Print("SafeDeleteContext:InitializeSecurityContext  Marshalling OUT buffer");
                        // Get unmanaged buffer with index 0 as the only one passed into PInvoke
                        outSecBuffer.size = outUnmanagedBuffer[0].count;
                        outSecBuffer.type = outUnmanagedBuffer[0].type;
                        if (outSecBuffer.size > 0)
                        {
                            outSecBuffer.token = new byte[outSecBuffer.size];
                            Marshal.Copy(outUnmanagedBuffer[0].token, outSecBuffer.token, 0, outSecBuffer.size);
                        }
                        else
                        {
                            outSecBuffer.token = null;
                        }
                    }
                }
            }
            finally
            {
                if (pinnedInBytes != null)
                {
                    for (int index = 0; index < pinnedInBytes.Length; index++)
                    {
                        if (pinnedInBytes[index].IsAllocated)
                            pinnedInBytes[index].Free();
                    }
                }
                if (pinnedOutBytes.IsAllocated)
                    pinnedOutBytes.Free();

                if (outFreeContextBuffer != null)
                    outFreeContextBuffer.Dispose();
            }

            GlobalLog.Leave("SafeDeleteContext::InitializeSecurityContext() unmanaged InitializeSecurityContext()", "errorCode:0x" + errorCode.ToString("x8") + " refContext:" + Logging.ObjectToString(refContext));

            return errorCode;
        }

        //
        // After PINvoke call the method will fix the handleTemplate.handle with the returned value.
        // The caller is responsible for creating a correct SafeFreeContextBuffer_XXX flavour or null can be passed if no handle is returned.
        //
        // Since it has a CER, this method can't have any references to imports from DLLs that may not exist on the system.
        //
        private static unsafe int MustRunInitializeSecurityContext_SECURITY(
                                                  ref SafeFreeCredentials inCredentials,
                                                  void* inContextPtr,
                                                  byte* targetName,
                                                  Interop.Secur32.ContextFlags inFlags,
                                                  Interop.Secur32.Endianness endianness,
                                                  Interop.Secur32.SecurityBufferDescriptor inputBuffer,
                                                  SafeDeleteContext outContext,
                                                  Interop.Secur32.SecurityBufferDescriptor outputBuffer,
                                                  ref Interop.Secur32.ContextFlags attributes,
                                                  SafeFreeContextBuffer handleTemplate)
        {
            int errorCode = (int)Interop.SecurityStatus.InvalidHandle;
            bool b1 = false;
            bool b2 = false;

            // Run the body of this method as a non-interruptible block.
            try
            {
                inCredentials.DangerousAddRef(ref b1);
                outContext.DangerousAddRef(ref b2);
            }
            catch (Exception e)
            {
                if (b1)
                {
                    inCredentials.DangerousRelease();
                    b1 = false;
                }
                if (b2)
                {
                    outContext.DangerousRelease();
                    b2 = false;
                }

                if (!(e is ObjectDisposedException))
                    throw;
            }
            finally
            {
                Interop.Secur32.SSPIHandle credentialHandle = inCredentials._handle;
                long timeStamp;

                if (!b1)
                {
                    // caller should retry
                    inCredentials = null;
                }
                else if (b1 && b2)
                {
                    errorCode = Interop.Secur32.InitializeSecurityContextW(
                                ref credentialHandle,
                                inContextPtr,
                                targetName,
                                inFlags,
                                0,
                                endianness,
                                inputBuffer,
                                0,
                                ref outContext._handle,
                                outputBuffer,
                                ref attributes,
                                out timeStamp);

                    //
                    // When a credential handle is first associated with the context we keep credential
                    // ref count bumped up to ensure ordered finalization.
                    // If the credential handle has been changed we de-ref the old one and associate the
                    //  context with the new cred handle but only if the call was successful.
                    if (outContext._EffectiveCredential != inCredentials && (errorCode & 0x80000000) == 0)
                    {
                        // Disassociate the previous credential handle
                        if (outContext._EffectiveCredential != null)
                            outContext._EffectiveCredential.DangerousRelease();
                        outContext._EffectiveCredential = inCredentials;
                    }
                    else
                    {
                        inCredentials.DangerousRelease();
                    }

                    outContext.DangerousRelease();

                    // The idea is that SSPI has allocated a block and filled up outUnmanagedBuffer+8 slot with the pointer.
                    if (handleTemplate != null)
                    {
                        handleTemplate.Set(((Interop.Secur32.SecurityBufferStruct*)outputBuffer.UnmanagedPointer)->token); //ATTN: on 64 BIT that is still +8 cause of 2* c++ unsigned long == 8 bytes
                        if (handleTemplate.IsInvalid)
                            handleTemplate.SetHandleAsInvalid();
                    }
                }


                if (inContextPtr == null && (errorCode & 0x80000000) != 0)
                {
                    // an error on the first call, need to set the out handle to invalid value
                    outContext._handle.SetToInvalid();
                }
            }

            return errorCode;
        }

        //-------------------------------------------------------------------
        internal unsafe static int AcceptSecurityContext(
            ref SafeFreeCredentials inCredentials,
            ref SafeDeleteContext refContext,
            Interop.Secur32.ContextFlags inFlags,
            Interop.Secur32.Endianness endianness,
            SecurityBuffer inSecBuffer,
            SecurityBuffer[] inSecBuffers,
            SecurityBuffer outSecBuffer,
            ref Interop.Secur32.ContextFlags outFlags)
        {
#if TRAVE
            GlobalLog.Enter("SafeDeleteContext::AcceptSecurityContex");
            GlobalLog.Print("    credential       = " + inCredentials.ToString());
            GlobalLog.Print("    refContext       = " + Logging.ObjectToString(refContext));

            GlobalLog.Print("    inFlags          = " + inFlags);
            //            GlobalLog.Print("    endianness       = " + endianness);
            //            GlobalLog.Print("    inSecBuffer      = " + SecurityBuffer.ToString(inSecBuffer));
            //
            if (inSecBuffers == null)
            {
                GlobalLog.Print("    inSecBuffers     = (null)");
            }
            else
            {
                GlobalLog.Print("    inSecBuffers[]   = length:" + inSecBuffers.Length);
                //                for (int index=0; index<inSecBuffers.Length; index++) { GlobalLog.Print("    inSecBuffers[" + index + "]   = " + SecurityBuffer.ToString(inSecBuffers[index])); }
            }
            //            GlobalLog.Print("    newContext       = {ref} inContext");
            //            GlobalLog.Print("    outSecBuffer     = " + SecurityBuffer.ToString(outSecBuffer));
            //            GlobalLog.Print("    outFlags         = {ref} " + outFlags);
            //            GlobalLog.Print("    timestamp        = null");
#endif
            GlobalLog.Assert(outSecBuffer != null, "SafeDeleteContext::AcceptSecurityContext()|outSecBuffer != null");
            GlobalLog.Assert(inSecBuffer == null || inSecBuffers == null, "SafeDeleteContext::AcceptSecurityContext()|inSecBuffer == null || inSecBuffers == null");

            if (inCredentials == null)
            {
                throw new ArgumentNullException("inCredentials");
            }

            Interop.Secur32.SecurityBufferDescriptor inSecurityBufferDescriptor = null;
            if (inSecBuffer != null)
            {
                inSecurityBufferDescriptor = new Interop.Secur32.SecurityBufferDescriptor(1);
            }
            else if (inSecBuffers != null)
            {
                inSecurityBufferDescriptor = new Interop.Secur32.SecurityBufferDescriptor(inSecBuffers.Length);
            }
            Interop.Secur32.SecurityBufferDescriptor outSecurityBufferDescriptor = new Interop.Secur32.SecurityBufferDescriptor(1);

            // actually this is returned in outFlags
            bool isSspiAllocated = (inFlags & Interop.Secur32.ContextFlags.AllocateMemory) != 0 ? true : false;

            int errorCode = -1;

            Interop.Secur32.SSPIHandle contextHandle = new Interop.Secur32.SSPIHandle();
            if (refContext != null)
                contextHandle = refContext._handle;

            // these are pinned user byte arrays passed along with SecurityBuffers
            GCHandle[] pinnedInBytes = null;
            GCHandle pinnedOutBytes = new GCHandle();
            // optional output buffer that may need to be freed
            SafeFreeContextBuffer outFreeContextBuffer = null;
            try
            {
                pinnedOutBytes = GCHandle.Alloc(outSecBuffer.token, GCHandleType.Pinned);
                var inUnmanagedBuffer = new Interop.Secur32.SecurityBufferStruct[inSecurityBufferDescriptor == null ? 1 : inSecurityBufferDescriptor.Count];
                fixed (void* inUnmanagedBufferPtr = inUnmanagedBuffer)
                {
                    if (inSecurityBufferDescriptor != null)
                    {
                        // Fix Descriptor pointer that points to unmanaged SecurityBuffers
                        inSecurityBufferDescriptor.UnmanagedPointer = inUnmanagedBufferPtr;
                        pinnedInBytes = new GCHandle[inSecurityBufferDescriptor.Count];
                        SecurityBuffer securityBuffer;
                        for (int index = 0; index < inSecurityBufferDescriptor.Count; ++index)
                        {
                            securityBuffer = inSecBuffer != null ? inSecBuffer : inSecBuffers[index];
                            if (securityBuffer != null)
                            {
                                // Copy the SecurityBuffer content into unmanaged place holder
                                inUnmanagedBuffer[index].count = securityBuffer.size;
                                inUnmanagedBuffer[index].type = securityBuffer.type;

                                // use the unmanaged token if it's not null; otherwise use the managed buffer
                                if (securityBuffer.unmanagedToken != null)
                                {
                                    inUnmanagedBuffer[index].token = securityBuffer.unmanagedToken.DangerousGetHandle();
                                }
                                else if (securityBuffer.token == null || securityBuffer.token.Length == 0)
                                {
                                    inUnmanagedBuffer[index].token = IntPtr.Zero;
                                }
                                else
                                {
                                    pinnedInBytes[index] = GCHandle.Alloc(securityBuffer.token, GCHandleType.Pinned);
                                    inUnmanagedBuffer[index].token = Marshal.UnsafeAddrOfPinnedArrayElement(securityBuffer.token, securityBuffer.offset);
                                }
#if TRAVE
                                GlobalLog.Print("SecBuffer: cbBuffer:" + securityBuffer.size + " BufferType:" + securityBuffer.type);
#endif
                            }
                        }
                    }

                    var outUnmanagedBuffer = new Interop.Secur32.SecurityBufferStruct[1];
                    fixed (void* outUnmanagedBufferPtr = outUnmanagedBuffer)
                    {
                        // Fix Descriptor pointer that points to unmanaged SecurityBuffers
                        outSecurityBufferDescriptor.UnmanagedPointer = outUnmanagedBufferPtr;
                        // Copy the SecurityBuffer content into unmanaged place holder
                        outUnmanagedBuffer[0].count = outSecBuffer.size;
                        outUnmanagedBuffer[0].type = outSecBuffer.type;

                        if (outSecBuffer.token == null || outSecBuffer.token.Length == 0)
                        {
                            outUnmanagedBuffer[0].token = IntPtr.Zero;
                        }
                        else
                        {
                            outUnmanagedBuffer[0].token = Marshal.UnsafeAddrOfPinnedArrayElement(outSecBuffer.token, outSecBuffer.offset);
                        }

                        if (isSspiAllocated)
                        {
                            outFreeContextBuffer = SafeFreeContextBuffer.CreateEmptyHandle();
                        }

                        if (refContext == null || refContext.IsInvalid)
                            refContext = new SafeDeleteContext_SECURITY();

                        errorCode = MustRunAcceptSecurityContext_SECURITY(
                                        ref inCredentials,
                                        contextHandle.IsZero ? null : &contextHandle,
                                        inSecurityBufferDescriptor,
                                        inFlags,
                                        endianness,
                                        refContext,
                                        outSecurityBufferDescriptor,
                                        ref outFlags,
                                        outFreeContextBuffer
                                        );

                        GlobalLog.Print("SafeDeleteContext:AcceptSecurityContext  Marshalling OUT buffer");
                        // Get unmanaged buffer with index 0 as the only one passed into PInvoke
                        outSecBuffer.size = outUnmanagedBuffer[0].count;
                        outSecBuffer.type = outUnmanagedBuffer[0].type;
                        if (outSecBuffer.size > 0)
                        {
                            outSecBuffer.token = new byte[outSecBuffer.size];
                            Marshal.Copy(outUnmanagedBuffer[0].token, outSecBuffer.token, 0, outSecBuffer.size);
                        }
                        else
                        {
                            outSecBuffer.token = null;
                        }
                    }
                }
            }
            finally
            {
                if (pinnedInBytes != null)
                {
                    for (int index = 0; index < pinnedInBytes.Length; index++)
                    {
                        if (pinnedInBytes[index].IsAllocated)
                            pinnedInBytes[index].Free();
                    }
                }

                if (pinnedOutBytes.IsAllocated)
                    pinnedOutBytes.Free();

                if (outFreeContextBuffer != null)
                    outFreeContextBuffer.Dispose();
            }

            GlobalLog.Leave("SafeDeleteContext::AcceptSecurityContex() unmanaged AcceptSecurityContex()", "errorCode:0x" + errorCode.ToString("x8") + " refContext:" + Logging.ObjectToString(refContext));

            return errorCode;
        }

        //
        // After PINvoke call the method will fix the handleTemplate.handle with the returned value.
        // The caller is responsible for creating a correct SafeFreeContextBuffer_XXX flavour or null can be passed if no handle is returned.
        //
        // Since it has a CER, this method can't have any references to imports from DLLs that may not exist on the system.
        //
        private static unsafe int MustRunAcceptSecurityContext_SECURITY(
                                                  ref SafeFreeCredentials inCredentials,
                                                  void* inContextPtr,
                                                  Interop.Secur32.SecurityBufferDescriptor inputBuffer,
                                                  Interop.Secur32.ContextFlags inFlags,
                                                  Interop.Secur32.Endianness endianness,
                                                  SafeDeleteContext outContext,
                                                  Interop.Secur32.SecurityBufferDescriptor outputBuffer,
                                                  ref Interop.Secur32.ContextFlags outFlags,
                                                  SafeFreeContextBuffer handleTemplate)
        {
            int errorCode = (int)Interop.SecurityStatus.InvalidHandle;
            bool b1 = false;
            bool b2 = false;

            // Run the body of this method as a non-interruptible block.
            try
            {
                inCredentials.DangerousAddRef(ref b1);
                outContext.DangerousAddRef(ref b2);
            }
            catch (Exception e)
            {
                if (b1)
                {
                    inCredentials.DangerousRelease();
                    b1 = false;
                }
                if (b2)
                {
                    outContext.DangerousRelease();
                    b2 = false;
                }
                if (!(e is ObjectDisposedException))
                    throw;
            }
            finally
            {
                Interop.Secur32.SSPIHandle credentialHandle = inCredentials._handle;
                long timeStamp;

                if (!b1)
                {
                    // caller should retry
                    inCredentials = null;
                }
                else if (b1 && b2)
                {
                    errorCode = Interop.Secur32.AcceptSecurityContext(
                                ref credentialHandle,
                                inContextPtr,
                                inputBuffer,
                                inFlags,
                                endianness,
                                ref outContext._handle,
                                outputBuffer,
                                ref outFlags,
                                out timeStamp);

                    //
                    // When a credential handle is first associated with the context we keep credential
                    // ref count bumped up to ensure ordered finalization.
                    // If the credential handle has been changed we de-ref the old one and associate the
                    //  context with the new cred handle but only if the call was successful.
                    if (outContext._EffectiveCredential != inCredentials && (errorCode & 0x80000000) == 0)
                    {
                        // Disassociate the previous credential handle
                        if (outContext._EffectiveCredential != null)
                            outContext._EffectiveCredential.DangerousRelease();
                        outContext._EffectiveCredential = inCredentials;
                    }
                    else
                    {
                        inCredentials.DangerousRelease();
                    }

                    outContext.DangerousRelease();

                    // The idea is that SSPI has allocated a block and filled up outUnmanagedBuffer+8 slot with the pointer.
                    if (handleTemplate != null)
                    {
                        handleTemplate.Set(((Interop.Secur32.SecurityBufferStruct*)outputBuffer.UnmanagedPointer)->token); //ATTN: on 64 BIT that is still +8 cause of 2* c++ unsigned long == 8 bytes
                        if (handleTemplate.IsInvalid)
                        {
                            handleTemplate.SetHandleAsInvalid();
                        }
                    }
                }

                if (inContextPtr == null && (errorCode & 0x80000000) != 0)
                {
                    // an error on the first call, need to set the out handle to invalid value
                    outContext._handle.SetToInvalid();
                }
            }

            return errorCode;
        }

        //
        //
        //
        internal unsafe static int CompleteAuthToken(
            ref SafeDeleteContext refContext,
            SecurityBuffer[] inSecBuffers)
        {
            GlobalLog.Enter("SafeDeleteContext::CompleteAuthToken");
            GlobalLog.Print("    refContext       = " + Logging.ObjectToString(refContext));
#if TRAVE
            GlobalLog.Print("    inSecBuffers[]   = length:" + inSecBuffers.Length);
            //            for (int index=0; index<inSecBuffers.Length; index++) { GlobalLog.Print("    inSecBuffers[" + index + "]   = " + SecurityBuffer.ToString(inSecBuffers[index])); }
#endif
            GlobalLog.Assert(inSecBuffers != null, "SafeDeleteContext::CompleteAuthToken()|inSecBuffers == null");
            var inSecurityBufferDescriptor = new Interop.Secur32.SecurityBufferDescriptor(inSecBuffers.Length);

            int errorCode = (int)Interop.SecurityStatus.InvalidHandle;

            // these are pinned user byte arrays passed along with SecurityBuffers
            GCHandle[] pinnedInBytes = null;

            var inUnmanagedBuffer = new Interop.Secur32.SecurityBufferStruct[inSecurityBufferDescriptor.Count];
            fixed (void* inUnmanagedBufferPtr = inUnmanagedBuffer)
            {
                // Fix Descriptor pointer that points to unmanaged SecurityBuffers
                inSecurityBufferDescriptor.UnmanagedPointer = inUnmanagedBufferPtr;
                pinnedInBytes = new GCHandle[inSecurityBufferDescriptor.Count];
                SecurityBuffer securityBuffer;
                for (int index = 0; index < inSecurityBufferDescriptor.Count; ++index)
                {
                    securityBuffer = inSecBuffers[index];
                    if (securityBuffer != null)
                    {
                        inUnmanagedBuffer[index].count = securityBuffer.size;
                        inUnmanagedBuffer[index].type = securityBuffer.type;

                        // use the unmanaged token if it's not null; otherwise use the managed buffer
                        if (securityBuffer.unmanagedToken != null)
                        {
                            inUnmanagedBuffer[index].token = securityBuffer.unmanagedToken.DangerousGetHandle();
                        }
                        else if (securityBuffer.token == null || securityBuffer.token.Length == 0)
                        {
                            inUnmanagedBuffer[index].token = IntPtr.Zero;
                        }
                        else
                        {
                            pinnedInBytes[index] = GCHandle.Alloc(securityBuffer.token, GCHandleType.Pinned);
                            inUnmanagedBuffer[index].token = Marshal.UnsafeAddrOfPinnedArrayElement(securityBuffer.token, securityBuffer.offset);
                        }
#if TRAVE
                        GlobalLog.Print("SecBuffer: cbBuffer:" + securityBuffer.size + " BufferType:" + securityBuffer.type);
#endif
                    }
                }

                Interop.Secur32.SSPIHandle contextHandle = new Interop.Secur32.SSPIHandle();
                if (refContext != null)
                {
                    contextHandle = refContext._handle;
                }
                try
                {
                    if (refContext == null || refContext.IsInvalid)
                    {
                        refContext = new SafeDeleteContext_SECURITY();
                    }

                    bool b = false;
                    try
                    {
                        refContext.DangerousAddRef(ref b);
                    }
                    catch (Exception e)
                    {
                        if (b)
                        {
                            refContext.DangerousRelease();
                            b = false;
                        }
                        if (!(e is ObjectDisposedException))
                            throw;
                    }
                    finally
                    {
                        if (b)
                        {
                            errorCode = Interop.Secur32.CompleteAuthToken(contextHandle.IsZero ? null : &contextHandle, inSecurityBufferDescriptor);
                            refContext.DangerousRelease();
                        }
                    }
                }
                finally
                {
                    if (pinnedInBytes != null)
                    {
                        for (int index = 0; index < pinnedInBytes.Length; index++)
                        {
                            if (pinnedInBytes[index].IsAllocated)
                            {
                                pinnedInBytes[index].Free();
                            }
                        }
                    }
                }
            }

            GlobalLog.Leave("SafeDeleteContext::CompleteAuthToken() unmanaged CompleteAuthToken()", "errorCode:0x" + errorCode.ToString("x8") + " refContext:" + Logging.ObjectToString(refContext));

            return errorCode;
        }
    }

    //======================================================================
    internal sealed class SafeDeleteContext_SECURITY : SafeDeleteContext
    {
        internal SafeDeleteContext_SECURITY() : base() { }

        override protected bool ReleaseHandle()
        {
            if (this._EffectiveCredential != null)
                this._EffectiveCredential.DangerousRelease();

            return Interop.Secur32.DeleteSecurityContext(ref _handle) == 0;
        }
    }
    //======================================================================

    // Based on SafeFreeContextBuffer
    internal abstract class SafeFreeContextBufferChannelBinding : ChannelBinding
    {
        private int size;

        public override int Size
        {
            get { return size; }
        }

        public override bool IsInvalid
        {
            get { return handle == new IntPtr(0) || handle == new IntPtr(-1); }
        }

        internal unsafe void Set(IntPtr value)
        {
            this.handle = value;
        }

        internal static SafeFreeContextBufferChannelBinding CreateEmptyHandle()
        {
            return new SafeFreeContextBufferChannelBinding_SECURITY();
        }

        public unsafe static int QueryContextChannelBinding(SafeDeleteContext phContext, Interop.Secur32.ContextAttribute contextAttribute, Bindings* buffer, SafeFreeContextBufferChannelBinding refHandle)
        {
            return QueryContextChannelBinding_SECURITY(phContext, contextAttribute, buffer, refHandle);
        }

        private unsafe static int QueryContextChannelBinding_SECURITY(SafeDeleteContext phContext, Interop.Secur32.ContextAttribute contextAttribute, Bindings* buffer, SafeFreeContextBufferChannelBinding refHandle)
        {
            int status = (int)Interop.SecurityStatus.InvalidHandle;
            bool b = false;

            // SCHANNEL only supports SECPKG_ATTR_ENDPOINT_BINDINGS and SECPKG_ATTR_UNIQUE_BINDINGS which
            // map to our enum ChannelBindingKind.Endpoint and ChannelBindingKind.Unique.
            if (contextAttribute != Interop.Secur32.ContextAttribute.EndpointBindings && 
                contextAttribute != Interop.Secur32.ContextAttribute.UniqueBindings)
            {
                return status;
            }

            // We don't want to be interrupted by thread abort exceptions or unexpected out-of-memory errors failing to jit
            // one of the following methods. So run within a CER non-interruptible block.
            try
            {
                phContext.DangerousAddRef(ref b);
            }
            catch (Exception e)
            {
                if (b)
                {
                    phContext.DangerousRelease();
                    b = false;
                }
                if (!(e is ObjectDisposedException))
                    throw;
            }
            finally
            {
                if (b)
                {
                    status = Interop.Secur32.QueryContextAttributesW(ref phContext._handle, contextAttribute, buffer);
                    phContext.DangerousRelease();
                }

                if (status == 0 && refHandle != null)
                {
                    refHandle.Set((*buffer).pBindings);
                    refHandle.size = (*buffer).BindingsLength;
                }

                if (status != 0 && refHandle != null)
                {
                    refHandle.SetHandleAsInvalid();
                }
            }

            return status;
        }
    }

    internal sealed class SafeFreeContextBufferChannelBinding_SECURITY : SafeFreeContextBufferChannelBinding
    {
        override protected bool ReleaseHandle()
        {
            return Interop.Secur32.FreeContextBuffer(handle) == 0;
        }
    }
}
