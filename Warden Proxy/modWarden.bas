Attribute VB_Name = "modWarden"
Option Explicit

Private Enum SHA1Versions
  Sha1 = 0
  BrokenSHA1 = 1
  LockdownSHA1 = 2
  WardenSHA1 = 3
  Max = &HFFFFFFFF
End Enum

Private Type SHA1Context
  IntermediateHash(0 To 4) As Long
  LengthLow As Long
  LengthHigh As Long
  MessageBlockIndex As Integer
  MessageBlock(0 To 63) As Byte
  Computed As Byte
  Corrupted As Byte
  Version As SHA1Versions
End Type

Private Type MD5Context
  IntermediateHash(0 To 3) As Long
  LengthLow As Long
  LengthHigh As Long
  MessageBlockIndex As Integer
  MessageBlock(0 To 63) As Byte
  Computed As Byte
  Corrupted As Byte
End Type

Private Type MedivRandomContext
  Index As Long
  Data(0 To 19) As Byte
  Source1(0 To 19) As Byte
  Source2(0 To 19) As Byte
End Type

Private Declare Sub rc4_init Lib "Warden.dll" (ByVal Key As String, ByVal Base As String, ByVal length As Long)
Private Declare Sub rc4_crypt Lib "Warden.dll" (ByVal Key As String, ByVal Data As String, ByVal length As Long)
Private Declare Sub rc4_crypt_data Lib "Warden.dll" (ByVal Data As String, ByVal DataLength As Long, ByVal Base As String, ByVal BaseLength As Long)

Private Declare Function sha1_reset Lib "Warden.dll" (ByRef Context As SHA1Context) As Long
Private Declare Function sha1_input Lib "Warden.dll" (ByRef Context As SHA1Context, ByVal Data As String, ByVal length As Long) As Long
Private Declare Function sha1_digest Lib "Warden.dll" (ByRef Context As SHA1Context, ByVal digest As String) As Long
Private Declare Function sha1_checksum Lib "Warden.dll" (ByVal Data As String, ByVal length As Long, ByVal Version As Long) As Long

Private Declare Function md5_reset Lib "Warden.dll" (ByRef Context As MD5Context) As Long
Private Declare Function md5_input Lib "Warden.dll" (ByRef Context As MD5Context, ByVal Data As String, ByVal length As Long) As Long
Private Declare Function md5_digest Lib "Warden.dll" (ByRef Context As MD5Context, ByVal digest As String) As Long
Private Declare Function md5_verify_data Lib "Warden.dll" (ByVal Data As String, ByVal length As Long, ByVal CorrectMD5 As String) As Boolean

Private Declare Sub mediv_random_init Lib "Warden.dll" (ByRef Context As MedivRandomContext, ByVal Seed As String, ByVal length As Long)
Private Declare Sub mediv_random_get_bytes Lib "Warden.dll" (ByRef Context As MedivRandomContext, ByVal Buffer As String, ByVal length As Long)

Private Declare Function warden_init Lib "Warden.dll" (ByVal SocketHandle As Long) As Long
Private Declare Function warden_data Lib "Warden.dll" (ByVal Instance As Long, ByVal Direction As Long, ByVal PacketID As Long, ByVal Data As String, ByVal length As Long) As Long
Private Declare Function warden_cleanup Lib "Warden.dll" (ByVal Instance As Long) As Long
Private Declare Function warden_config Lib "Warden.dll" (ByVal Instance As Long, ByVal ConfigBit As Long, ByVal Enabled As Byte) As Long
Private Declare Function warden_set_data_file Lib "Warden.dll" (ByVal Instance As Long, ByVal FilePath As String, ByVal length As Long) As Long

Private Const WARDEN_SEND              As Long = &H0
Private Const WARDEN_RECV              As Long = &H1
Private Const WARDEN_BNCS              As Long = &H2

Private Const WARDEN_IGNORE                  As Long = &H0 '//Not a warden packet, Handle internally
Private Const WARDEN_SUCCESS                 As Long = &H1 '//All Went Well, Don't handle the packet Internally
Private Const WARDEN_UNKNOWN_PROTOCOL        As Long = &H2 '//Not used, will be when adding support for MCP/UDP
Private Const WARDEN_UNKNOWN_SUBID           As Long = &H3 '//Unknown Sub-ID [Not 0x00, 0x01, 0x02, or 0x05]
Private Const WARDEN_RAW_FAILURE             As Long = &H4 '//The module was not able to handle the packet itself
Private Const WARDEN_PACKET_FAILURE          As Long = &H5 '//Something went HORRIBLY wrong in warden_packet, should NEVER happen.
Private Const WARDEN_INIT_FAILURE            As Long = &H6 '//Calling Init() in the module failed
Private Const WARDEN_LOAD_FILE_FAILURE       As Long = &H7 '//Could not load module from file [Not to bad, prolly just dosen't exist]
Private Const WARDEN_LOAD_MD5_FAILURE        As Long = &H8 '//Failed MD5 checksum when loading module [Either Bad tranfer or HD file corrupt]
Private Const WARDEN_LOAD_INVALID_SIGNATURE  As Long = &H9 '//Module failed RSA verification
Private Const WARDEN_LOAD_DECOMPRESS_FAILURE As Long = &HA '//Module failed to decompress properly
Private Const WARDEN_LOAD_PREP_FAILURE       As Long = &HB '//Module prepare failed, Usually if module is corrupt
Private Const WARDEN_CHECK_UNKNOWN_COMMAND   As Long = &HC '//Unknown sub-command in CHEAT_CHECKS
Private Const WARDEN_CHECK_TO_MANY_LIBS      As Long = &HD '//There were more then 4 libraries in a single 0x02 packet [this is eww yes, but I'll figure out a beter way later]
Private Const WARDEN_MEM_UNKNOWN_PRODUCT     As Long = &HE '//The product from 0x50 != WC3, SC, or D2
Private Const WARDEN_MEM_UNKNOWN_SEGMENT     As Long = &HF '//Could not read segment from ini file


Public Const WARDEN_CONFIG_SAVE_CHECKS    As Long = 1  '//Save Information about cheat checks (Opcode 0x02) to Data File
Public Const WARDEN_CONFIG_SAVE_UNKNOWN   As Long = 2  '//Save Unknown information (use in conjunction with Debug mode to get new Warden offsets)
Public Const WARDEN_CONFIG_LOG_CHECKS     As Long = 4  '//Log ALL information about checks that happen, in real time
Public Const WARDEN_CONFIG_LOG_PACKETS    As Long = 8  '//Log ALL decoded Warden packet data
Public Const WARDEN_CONFIG_DEBUG_MODE     As Long = 16 '//Debug mode, does a lot of shit u.u
Public Const WARDEN_CONFIG_USE_GAME_FILES As Long = 32 '//Will attempt to grab unknown Mem Check offsets from the game file specified
                                                       '//  Will try to load library the file, using the path specified in the INI EXA:
                                                       '//[Files_WAR3]
                                                       '//Default=C:\Program Files\Warcraft III\WAR3.exe
                                                       '//Game.dll=C:\Program Files\Warcraft III\Game.dll

Public WardenInstance As Long

'======================================================================================================
'CheckRevision Related Stuff
Private Declare Function check_revision Lib "Warden.dll" ( _
    ByVal ArchiveTime As String, ByVal ArchiveName As String, ByVal Seed As String, _
    ByVal INIFile As String, ByVal INIHeader As String, _
    ByRef Version As Long, ByRef Checksum As Long, ByVal Result As String) As Long
Private Declare Function crev_max_result Lib "Warden.dll" () As Long
Private Declare Function crev_error_description Lib "Warden.dll" (ByVal ErrorCode As Long, ByVal Description As String, ByVal Size As Long) As Long

Public Sub TestCRev()
    Dim sFileTime As String
    Dim sFileName As String
    Dim sSeed     As String
    sFileTime = HexToStr("0031EF00705FC701")
    sFileName = "ver-IX86-5.mpq"
    sSeed = "A=1309005226 C=1705134259 B=4173766578 4 A=A-S B=B-C C=C^A A=A-B"
    'Version  = 0x011801E6
    'Checksum = 0x31EB10D4
    'Result   = war3.exe 07/07/09 21:20:52 471040

    Dim lRet      As Long
    Dim lVersion  As Long
    Dim lChecksum As Long
    Dim sResult   As String
    Dim i         As Integer
    
    
    sResult = String$(crev_max_result, Chr$(0))
    
    lRet = check_revision(sFileTime, sFileName, sSeed, App.Path & "\Warden.ini", "CRev_WAR3", lVersion, lChecksum, sResult)
    i = InStr(1, sResult, Chr$(0))
    sResult = Left$(sResult, i)
    
    Debug.Print StringFormat("Max Result: {0}", crev_max_result)
    Debug.Print StringFormat("Return:     {0}", lRet)
    Debug.Print StringFormat("Version:    0x{0} 0x011801E6", ZeroOffset(lVersion, 8))
    Debug.Print StringFormat("Checksum:   0x{0} 0x31EB10D4", ZeroOffset(lChecksum, 8))
    Debug.Print StringFormat("Result:     {0}", sResult)
    
    Dim x As Integer
    For x = 0 To 10
        sResult = String$(crev_max_result, Chr$(0))
        lRet = crev_error_description(x, sResult, Len(sResult))
        i = InStr(1, sResult, Chr$(0))
        If (i > 0) Then sResult = Left$(sResult, i)
        Debug.Print StringFormat("Result:     {0}", sResult)
    Next x
    
End Sub
'======================================================================================================
Public Sub WardenCleanup(Instance As Long)
  Call warden_cleanup(Instance)
End Sub

Public Function WardenInitilize(ByVal SocketHandle As Long) As Long
  WardenInitilize = warden_init(SocketHandle)
End Function

Public Function WardenData(Instance As Long, sData As String, Send As Boolean) As Boolean
  Dim ID As Long
  Dim Result As Long
  Dim Data As String

  ID = Asc(Mid(sData, 2, 1))
  Data = Mid$(sData, 5)
  
  Result = warden_data(Instance, WARDEN_BNCS Or IIf(Send, WARDEN_SEND, WARDEN_RECV), ID, Data, Len(Data))
  
  Select Case Result
    'Case WARDEN_SUCCESS: '//All Went Well, Don't handle the packet Internally
    'Case WARDEN_UNKNOWN_PROTOCOL '//Not used, will be when adding support for MCP/UDP
    Case WARDEN_UNKNOWN_SUBID: '//Unknown Sub-ID [Not 0x00, 0x01, 0x02, or 0x05]
        frmMain.AddChat vbRed, "[Warden] Unknown sub-command 0x" & Right("00" & Hex(Asc(Left$(Data, 1))), 2) & ", you will be disconnected soon"
        frmMain.AddChat vbYellow, "[Warden] Packet Data:" & vbNewLine & DebugOutput(Data)
        
    Case WARDEN_RAW_FAILURE: '//The module was not able to handle the packet itself (most likely 0x05)
        frmMain.AddChat vbRed, "[Warden] Module was unable to handle a packet, you will be disconnected soon"
        frmMain.AddChat vbYellow, "[Warden] Packet Data:" & vbNewLine & DebugOutput(Data)
        
    Case WARDEN_PACKET_FAILURE: '//Something went HORRIBLY wrong in warden_packet, should NEVER happen.
        frmMain.AddChat vbRed, "[Warden] Something wen't horribly wrong in Warden_Packet(), you will be disconnected soon"
        frmMain.AddChat vbYellow, "[Warden] Packet Data:" & vbNewLine & DebugOutput(Data)
        
    Case WARDEN_INIT_FAILURE: '//Calling Init() in the module failed
        frmMain.AddChat vbRed, "[Warden] Unable to init() the module, you will be disconnected soon"
    
    'case WARDEN_LOAD_FILE_FAILURE '//Could not load module from file [Not to bad, prolly just dosen't exist] This should never come up
    
    Case WARDEN_LOAD_MD5_FAILURE: '//Failed MD5 checksum when loading module [Either Bad tranfer or HD file corrupt]
        frmMain.AddChat vbRed, "[Warden] Transfer failed, MD5 checksum incorrect, you will be disconnected soon"
        
    Case WARDEN_LOAD_INVALID_SIGNATURE: '//Module failed RSA verification
        frmMain.AddChat vbRed, "[Warden] Transfer failed, Invalid RSA signature, you will be disconnected soon"
        
    Case WARDEN_LOAD_DECOMPRESS_FAILURE: '//Module failed to decompress properly
        frmMain.AddChat vbRed, "[Warden] Failed to decompress module, you will be disconnected soon"
        
    Case WARDEN_LOAD_PREP_FAILURE: '//Module prepare failed, Usually if module is corrupt
        frmMain.AddChat vbRed, "[Warden] Failed to prep module, you will be disconnected soon"
        
    Case WARDEN_CHECK_UNKNOWN_COMMAND: '//Unknown sub-command in CHEAT_CHECKS
        frmMain.AddChat vbRed, "[Warden] Unknown Sub-Command in Cheat Checks, you will be disconnected soon"
        frmMain.AddChat vbYellow, "[Warden] Packet Data: " & vbNewLine & DebugOutput(Data)
        
    Case WARDEN_CHECK_TO_MANY_LIBS: '//There were more then 4 libraries in a single 0x02 packet [this is eww yes, but I'll figure out a beter way later]
        frmMain.AddChat vbRed, "[Warden] To many libraries in Cheat Check, you will be disconnected soon"
        frmMain.AddChat vbYellow, "[Warden] Packet Data: " & vbNewLine & DebugOutput(Data)
    
    Case WARDEN_MEM_UNKNOWN_PRODUCT: '//The product from 0x50 != WC3, SC, or D2
        frmMain.AddChat vbRed, "[Warden] Unknown product code form SID_AUTH_INFO, you will be diconnected soon"
        
    Case WARDEN_MEM_UNKNOWN_SEGMENT: '//Could not read segment from ini file
        frmMain.AddChat vbRed, "[Warden] Could not read segment from Warden.ini, you will be disconnected soon"
        frmMain.AddChat vbRed, "[Warden] Make sure you've got the latest Warden data from http://www.stealthbot.net/board/index.php?showtopic=41491"
        frmMain.AddChat vbYellow, "[Warden] Packet Data: " & vbNewLine & DebugOutput(Data)
  End Select
    
  WardenData = (Result <> WARDEN_IGNORE)
End Function

Public Function WardenSetConfigBit(Instance As Long, ConfigBit As Long, Status As Boolean) As Long
    WardenSetConfigBit = warden_config(Instance, ConfigBit, IIf(Status, 1, 0))
End Function

