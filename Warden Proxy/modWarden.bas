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

Private Declare Sub rc4_init Lib "Warden.dll" (ByVal Key As String, ByVal Base As String, ByVal Length As Long)
Private Declare Sub rc4_crypt Lib "Warden.dll" (ByVal Key As String, ByVal Data As String, ByVal Length As Long)
Private Declare Sub rc4_crypt_data Lib "Warden.dll" (ByVal Data As String, ByVal DataLength As Long, ByVal Base As String, ByVal BaseLength As Long)
Private Declare Function rc4_buffer_size Lib "Warden.dll" () As Long

Private Declare Function rsa_create Lib "Warden.dll" (ByVal RSA As String, ByVal CreateType As Long, ByVal KeyData As String) As Long
Private Declare Function rsa_hash Lib "Warden.dll" (ByVal RSA As String, ByVal HashType As Long, ByVal Padding As Long, ByVal Data As String, ByVal DataLength As Long, ByVal Buffer As String) As Long
Private Declare Function rsa_hash_size Lib "Warden.dll" (ByVal RSA As String) As Long
Private Declare Function rsa_buffer_size Lib "Warden.dll" () As Long
'Private Declare Sub rsa_free Lib "Warden.dll" (ByVal RSA As String)

Private Declare Function aes_buffer_size Lib "Warden.dll" () As Long
Private Declare Function aes_create Lib "Warden.dll" (ByVal Key As String, ByVal KeyType As Long, ByVal Seed As String, ByVal Length As Long) As Long
Private Declare Function aes_crypt Lib "Warden.dll" (ByVal Key As String, ByVal CryptType As Long, ByVal Encrypt As Long, ByVal InitVec As String, ByVal Length As Long, ByVal Data As String, ByVal Buffer As String) As Long


Private Declare Function sha1_reset Lib "Warden.dll" (ByRef Context As SHA1Context) As Long
Private Declare Function sha1_input Lib "Warden.dll" (ByRef Context As SHA1Context, ByVal Data As String, ByVal Length As Long) As Long
Private Declare Function sha1_digest Lib "Warden.dll" (ByRef Context As SHA1Context, ByVal digest As String) As Long
Private Declare Function sha1_checksum Lib "Warden.dll" (ByVal Data As String, ByVal Length As Long, ByVal Version As Long) As Long

Private Declare Function md5_reset Lib "Warden.dll" (ByRef Context As MD5Context) As Long
Private Declare Function md5_input Lib "Warden.dll" (ByRef Context As MD5Context, ByVal Data As String, ByVal Length As Long) As Long
Private Declare Function md5_digest Lib "Warden.dll" (ByRef Context As MD5Context, ByVal digest As String) As Long
Private Declare Function md5_verify_data Lib "Warden.dll" (ByVal Data As String, ByVal Length As Long, ByVal CorrectMD5 As String) As Boolean

Private Declare Sub mediv_random_init Lib "Warden.dll" (ByRef Context As MedivRandomContext, ByVal Seed As String, ByVal Length As Long)
Private Declare Sub mediv_random_get_bytes Lib "Warden.dll" (ByRef Context As MedivRandomContext, ByVal Buffer As String, ByVal Length As Long)

Private Declare Function warden_init Lib "Warden.dll" (ByVal SocketHandle As Long) As Long
Private Declare Function warden_data Lib "Warden.dll" (ByVal Instance As Long, ByVal Direction As Long, ByVal PacketID As Long, ByVal Data As String, ByVal Length As Long) As Long
Private Declare Function warden_cleanup Lib "Warden.dll" (ByVal Instance As Long) As Long
Private Declare Function warden_config Lib "Warden.dll" (ByVal Instance As Long, ByVal ConfigBit As Long, ByVal Enabled As Byte) As Long
Private Declare Function warden_set_data_file Lib "Warden.dll" (ByVal Instance As Long, ByVal FilePath As String, ByVal Length As Long) As Long

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

Private Const GSP_PRIVATE_KEY As String = "MIIEogIBAAKCAQEA3XK9BWuIHIS3R6za4WU/mQ0WlsPD/ErtzSTw2ZmbhI0lyKcQ" & vbNewLine & _
                                          "Ugk0aRIOaq4vTE+EpRtI6hvhH4AIm+15sWPqxpfuNR0Dvigse+BhuypFsqI+AWiL" & vbNewLine & _
                                          "dj5RrPSzrLcqWgjE5zSjUG4OmxS4NJJRY9UMNaEhtqsrgrFFj4iMX07bz6Joyp85" & vbNewLine & _
                                          "CHpGJhmFjPwU60OlUkGKwvs6TeQXUZlH9ypzXkNAhF4uDchTgEX7A/8yrqHzPx7/" & vbNewLine & _
                                          "r2T0Lww7kp106ACdy9wXTpq5v3tmfNZbZ7K0bEB4g8Ez43Hew1P5b/tabUV4pZL0" & vbNewLine & _
                                          "LkvDCA78ll8FHeuJjZA3+DKlEgyA2EWTs98VTQIDAQABAoIBAC65evCd08ZQqmtR" & vbNewLine & _
                                          "KY3NUzHz9QQyojOli69xT/BZ3NqG/aXsuiDVGF3jFW+k+Q3c6Vv8+dGLuGBxH1/n" & vbNewLine & _
                                          "J3oqXuswO26xhIym5Vvt6DEZpkMewH6DlImKdKlNqGuU6ja9Cu7NyHe8ARDvuj49" & vbNewLine & _
                                          "cTbjSQQ3z2k/jJqy1L6ITTX+6ZpRgZd9m/Ng5O0GBcoSiUjysfLgs5m5lHWCojL+" & vbNewLine & _
                                          "ppxqhsWXDM2ejIFGncGok798NNps+OkAM9EwEHcEI7qBo/UEsgXwnmlUvsyBvtq3" & vbNewLine & _
                                          "7NS/znsJlOT/PfbS3i0gIac6AmA0qh86zN+uC5yl44aY+WpwPqBua6eeKkpk3xAo" & vbNewLine & _
                                          "LrCRxHECgYEA/689gaRf0ihJ5WpD/cq6XLFwxuu4/CmmNjYpTwol2S3lGnq03RLZ" & vbNewLine & _
                                          "FhklvMKIkhfuaOLyrHgUWaYZVr2KBUU81qwHTVEZeN6rWPeXTsfgBnpShIYYXqBN" & vbNewLine & _
                                          "ePyqVDuISs44Lsi74fhSNrqai6ow6GQYlZewcdjS2zVc35G1of/cWNMCgYEA3biv" & vbNewLine & _
                                          "L49okrATQfBbdl5L6hueqNc8pfrv6EKYcw5SE48fFeHCToorKpaf4kf7GemITldD" & vbNewLine & _
                                          "29FFwukhyt1rJJI9Kvj6jKN49QZr3xS1d8QY0lOHnRRRLIg3x+VaD7RYOWuHbqs1" & vbNewLine & _
                                          "MKyzgeKkpWq6EkuaW2ZEQwL6cvzqGsbo1CRqBV8CgYBMNqEf1q5VR3sXbkCMEvTQ" & vbNewLine & _
                                          "EngqYzNFvuhzelt/2ueDQCHtbawhxa993csY4+evnICNNTDe5gAy5MbiyyasAYJr" & vbNewLine & _
                                          "/uVCT61HESCEKXEpo3yMkcOtCweSlTfim3XuG7y5h5TJpT4T0mA3PhI5FWb0rnmB" & vbNewLine & _
                                          "hbCrjtTzUIm5foZkno7AzwKBgD2PTXSTCKHRqUchiQNwYvt497BBMmGTLpD6DIHF" & vbNewLine & _
                                          "dBxiHGti5yQPULTeZT3aZmlnYaT+raSWkhvvxqYgm+Lnh3wq7MWnjanaQpEJmujJ" & vbNewLine & _
                                          "1WpwLrL6NR98IqCpmTvLAsPOiye6+WWuTZi+aKBU5Zy2yQCfgExqw0ax2f3dRD/C" & vbNewLine & _
                                          "bH1ZAoGAOJ/pLNpetFyE/aaD0jBfMA6UACdutjWT4vFGmk/GwBh3/sHoMbON2c/P" & vbNewLine & _
                                          "OeEM/N3/ZODOZHzXB1ALgWIjeoP2TegBfbniHf2d+j1/VRMTiYEMv3ws06YiWMLJ" & vbNewLine & _
                                          "ioX2ZNntCCPlIti48TeFs0etqcHQgQ5rSLblyde3RIuRcqatQko="

Public Sub Test()
    Dim RSASize As Long
    Dim AES     As String
    Dim lRet    As Long
    Dim Hash    As String
    Dim Data    As String
    Dim Seed    As String
    Dim IV      As String
    Seed = HexToStr("95A8EE8E89979B9EFDCBC6EB9797528D")
    IV = String$(16, Chr$(0))
    Data = HexToStr("4EC137A426DABF8AA0BEB8BC0C2B89D6")
    
    lRet = aes_buffer_size
    Debug.Print "AES Size: " & lRet
    
    AES = String$(lRet, Chr$(0))
    lRet = aes_create(AES, 1, Seed, Len(Seed))
    Debug.Print "AES Create: " & lRet
    'Debug.Print "AES: "
    'Debug.Print DebugOutput(AES)
    
    Hash = String$(Len(Data), Chr$(0))
    
    lRet = aes_crypt(AES, 0, 0, IV, Len(Data), Data, Hash)
    
    Debug.Print "AES Hash: " & lRet
    Debug.Print "Hash: " & DebugOutput(Hash)
    Debug.Print "IV:   " & DebugOutput(IV)
    
    
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

