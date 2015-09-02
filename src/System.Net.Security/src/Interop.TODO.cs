// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Cryptography.X509Certificates;

internal static partial class Interop
{



    internal enum CertificateProblem
    {
        OK = 0x00000000,
        TrustNOSIGNATURE = unchecked((int)0x800B0100),
        CertEXPIRED = unchecked((int)0x800B0101),
        CertVALIDITYPERIODNESTING = unchecked((int)0x800B0102),
        CertROLE = unchecked((int)0x800B0103),
        CertPATHLENCONST = unchecked((int)0x800B0104),
        CertCRITICAL = unchecked((int)0x800B0105),
        CertPURPOSE = unchecked((int)0x800B0106),
        CertISSUERCHAINING = unchecked((int)0x800B0107),
        CertMALFORMED = unchecked((int)0x800B0108),
        CertUNTRUSTEDROOT = unchecked((int)0x800B0109),
        CertCHAINING = unchecked((int)0x800B010A),
        CertREVOKED = unchecked((int)0x800B010C),
        CertUNTRUSTEDTESTROOT = unchecked((int)0x800B010D),
        CertREVOCATION_FAILURE = unchecked((int)0x800B010E),
        CertCN_NO_MATCH = unchecked((int)0x800B010F),
        CertWRONG_USAGE = unchecked((int)0x800B0110),
        TrustEXPLICITDISTRUST = unchecked((int)0x800B0111),
        CertUNTRUSTEDCA = unchecked((int)0x800B0112),
        CertINVALIDPOLICY = unchecked((int)0x800B0113),
        CertINVALIDNAME = unchecked((int)0x800B0114),

        CryptNOREVOCATIONCHECK = unchecked((int)0x80092012),
        CryptREVOCATIONOFFLINE = unchecked((int)0x80092013),

        TrustSYSTEMERROR = unchecked((int)0x80096001),
        TrustNOSIGNERCERT = unchecked((int)0x80096002),
        TrustCOUNTERSIGNER = unchecked((int)0x80096003),
        TrustCERTSIGNATURE = unchecked((int)0x80096004),
        TrustTIMESTAMP = unchecked((int)0x80096005),
        TrustBADDIGEST = unchecked((int)0x80096010),
        TrustBASICCONSTRAINTS = unchecked((int)0x80096019),
        TrustFINANCIALCRITERIA = unchecked((int)0x8009601E),
    }

    // #define ISC_REQ_DELEGATE                0x00000001
    // #define ISC_REQ_MUTUAL_AUTH             0x00000002
    // #define ISC_REQ_REPLAY_DETECT           0x00000004
    // #define ISC_REQ_SEQUENCE_DETECT         0x00000008
    // #define ISC_REQ_CONFIDENTIALITY         0x00000010
    // #define ISC_REQ_USE_SESSION_KEY         0x00000020
    // #define ISC_REQ_PROMPT_FOR_CREDS        0x00000040
    // #define ISC_REQ_USE_SUPPLIED_CREDS      0x00000080
    // #define ISC_REQ_ALLOCATE_MEMORY         0x00000100
    // #define ISC_REQ_USE_DCE_STYLE           0x00000200
    // #define ISC_REQ_DATAGRAM                0x00000400
    // #define ISC_REQ_CONNECTION              0x00000800
    // #define ISC_REQ_CALL_LEVEL              0x00001000
    // #define ISC_REQ_FRAGMENT_SUPPLIED       0x00002000
    // #define ISC_REQ_EXTENDED_ERROR          0x00004000
    // #define ISC_REQ_STREAM                  0x00008000
    // #define ISC_REQ_INTEGRITY               0x00010000
    // #define ISC_REQ_IDENTIFY                0x00020000
    // #define ISC_REQ_NULL_SESSION            0x00040000
    // #define ISC_REQ_MANUAL_CRED_VALIDATION  0x00080000
    // #define ISC_REQ_RESERVED1               0x00100000
    // #define ISC_REQ_FRAGMENT_TO_FIT         0x00200000
    // #define ISC_REQ_HTTP                    0x10000000
    // Win7 SP1 +
    // #define ISC_REQ_UNVERIFIED_TARGET_NAME  0x20000000  

    // #define ASC_REQ_DELEGATE                0x00000001
    // #define ASC_REQ_MUTUAL_AUTH             0x00000002
    // #define ASC_REQ_REPLAY_DETECT           0x00000004
    // #define ASC_REQ_SEQUENCE_DETECT         0x00000008
    // #define ASC_REQ_CONFIDENTIALITY         0x00000010
    // #define ASC_REQ_USE_SESSION_KEY         0x00000020
    // #define ASC_REQ_ALLOCATE_MEMORY         0x00000100
    // #define ASC_REQ_USE_DCE_STYLE           0x00000200
    // #define ASC_REQ_DATAGRAM                0x00000400
    // #define ASC_REQ_CONNECTION              0x00000800
    // #define ASC_REQ_CALL_LEVEL              0x00001000
    // #define ASC_REQ_EXTENDED_ERROR          0x00008000
    // #define ASC_REQ_STREAM                  0x00010000
    // #define ASC_REQ_INTEGRITY               0x00020000
    // #define ASC_REQ_LICENSING               0x00040000
    // #define ASC_REQ_IDENTIFY                0x00080000
    // #define ASC_REQ_ALLOW_NULL_SESSION      0x00100000
    // #define ASC_REQ_ALLOW_NON_USER_LOGONS   0x00200000
    // #define ASC_REQ_ALLOW_CONTEXT_REPLAY    0x00400000
    // #define ASC_REQ_FRAGMENT_TO_FIT         0x00800000
    // #define ASC_REQ_FRAGMENT_SUPPLIED       0x00002000
    // #define ASC_REQ_NO_TOKEN                0x01000000
    // #define ASC_REQ_HTTP                    0x10000000

    [Flags]
    internal enum ContextFlags
    {
        Zero = 0,
        // The server in the transport application can
        // build new security contexts impersonating the
        // client that will be accepted by other servers
        // as the client's contexts.
        Delegate = 0x00000001,
        // The communicating parties must authenticate
        // their identities to each other. Without MutualAuth,
        // the client authenticates its identity to the server.
        // With MutualAuth, the server also must authenticate
        // its identity to the client.
        MutualAuth = 0x00000002,
        // The security package detects replayed packets and
        // notifies the caller if a packet has been replayed.
        // The use of this flag implies all of the conditions
        // specified by the Integrity flag.
        ReplayDetect = 0x00000004,
        // The context must be allowed to detect out-of-order
        // delivery of packets later through the message support
        // functions. Use of this flag implies all of the
        // conditions specified by the Integrity flag.
        SequenceDetect = 0x00000008,
        // The context must protect data while in transit.
        // Confidentiality is supported for NTLM with Microsoft
        // Windows NT version 4.0, SP4 and later and with the
        // Kerberos protocol in Microsoft Windows 2000 and later.
        Confidentiality = 0x00000010,
        UseSessionKey = 0x00000020,
        AllocateMemory = 0x00000100,

        // Connection semantics must be used.
        Connection = 0x00000800,

        // Client applications requiring extended error messages specify the
        // ISC_REQ_EXTENDED_ERROR flag when calling the InitializeSecurityContext
        // Server applications requiring extended error messages set
        // the ASC_REQ_EXTENDED_ERROR flag when calling AcceptSecurityContext.
        InitExtendedError = 0x00004000,
        AcceptExtendedError = 0x00008000,
        // A transport application requests stream semantics
        // by setting the ISC_REQ_STREAM and ASC_REQ_STREAM
        // flags in the calls to the InitializeSecurityContext
        // and AcceptSecurityContext functions
        InitStream = 0x00008000,
        AcceptStream = 0x00010000,
        // Buffer integrity can be verified; however, replayed
        // and out-of-sequence messages will not be detected
        InitIntegrity = 0x00010000,       // ISC_REQ_INTEGRITY
        AcceptIntegrity = 0x00020000,       // ASC_REQ_INTEGRITY

        InitManualCredValidation = 0x00080000,   // ISC_REQ_MANUAL_CRED_VALIDATION
        InitUseSuppliedCreds = 0x00000080,   // ISC_REQ_USE_SUPPLIED_CREDS
        InitIdentify = 0x00020000,   // ISC_REQ_IDENTIFY
        AcceptIdentify = 0x00080000,   // ASC_REQ_IDENTIFY

        ProxyBindings = 0x04000000,   // ASC_REQ_PROXY_BINDINGS
        AllowMissingBindings = 0x10000000,   // ASC_REQ_ALLOW_MISSING_BINDINGS

        UnverifiedTargetName = 0x20000000,   // ISC_REQ_UNVERIFIED_TARGET_NAME
    }

    internal enum BufferType
    {
        Empty = 0x00,
        Data = 0x01,
        Token = 0x02,
        Parameters = 0x03,
        Missing = 0x04,
        Extra = 0x05,
        Trailer = 0x06,
        Header = 0x07,
        Padding = 0x09,    // non-data padding
        Stream = 0x0A,
        ChannelBindings = 0x0E,
        TargetHost = 0x10,
        ReadOnlyFlag = unchecked((int)0x80000000),
        ReadOnlyWithChecksum = 0x10000000
    }

    internal class SecurityBuffer
    {
        public int size;
        public Interop.BufferType type;
        public byte[] token;
        public SafeHandle unmanagedToken;
        public int offset;

        public SecurityBuffer(byte[] data, int offset, int size, Interop.BufferType tokentype)
        {
            GlobalLog.Assert(offset >= 0 && offset <= (data == null ? 0 : data.Length), "SecurityBuffer::.ctor", "'offset' out of range.  [" + offset + "]");
            GlobalLog.Assert(size >= 0 && size <= (data == null ? 0 : data.Length - offset), "SecurityBuffer::.ctor", "'size' out of range.  [" + size + "]");

            this.offset = data == null || offset < 0 ? 0 : Math.Min(offset, data.Length);
            this.size = data == null || size < 0 ? 0 : Math.Min(size, data.Length - this.offset);
            this.type = tokentype;
            this.token = size == 0 ? null : data;
        }

        public SecurityBuffer(byte[] data, Interop.BufferType tokentype)
        {
            this.size = data == null ? 0 : data.Length;
            this.type = tokentype;
            this.token = size == 0 ? null : data;
        }

        public SecurityBuffer(int size, Interop.BufferType tokentype)
        {
            GlobalLog.Assert(size >= 0, "SecurityBuffer::.ctor", "'size' out of range.  [" + size + "]");

            this.size = size;
            this.type = tokentype;
            this.token = size == 0 ? null : new byte[size];
        }

        public SecurityBuffer(ChannelBinding binding)
        {
            this.size = (binding == null ? 0 : binding.Size);
            this.type = Interop.BufferType.ChannelBindings;
            this.unmanagedToken = binding;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct AuthIdentity
    {
        // see SEC_WINNT_AUTH_IDENTITY_W
        internal string UserName;
        internal int UserNameLength;
        internal string Domain;
        internal int DomainLength;
        internal string Password;
        internal int PasswordLength;
        internal int Flags;

        internal AuthIdentity(string userName, string password, string domain)
        {
            UserName = userName;
            UserNameLength = userName == null ? 0 : userName.Length;
            Password = password;
            PasswordLength = password == null ? 0 : password.Length;
            Domain = domain;
            DomainLength = domain == null ? 0 : domain.Length;
            // Flags are 2 for Unicode and 1 for ANSI. We use 2 on NT and 1 on Win9x.
            Flags = 2;
        }
        public override string ToString()
        {
            return Logging.ObjectToString(Domain) + "\\" + Logging.ObjectToString(UserName);
        }
    }
}
