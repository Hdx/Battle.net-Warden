VERSION 5.00
Object = "{248DD890-BB45-11CF-9ABC-0080C7E7B78D}#1.0#0"; "MSWINSCK.OCX"
Object = "{3B7C8863-D78F-101B-B9B5-04021C009402}#1.2#0"; "RICHTX32.OCX"
Object = "{48E59290-9880-11CF-9754-00AA00C00908}#1.0#0"; "msinet.ocx"
Begin VB.Form frmMain 
   Caption         =   "Hdx Warden Proxy"
   ClientHeight    =   4995
   ClientLeft      =   60
   ClientTop       =   345
   ClientWidth     =   11160
   BeginProperty Font 
      Name            =   "Times New Roman"
      Size            =   8.25
      Charset         =   0
      Weight          =   400
      Underline       =   0   'False
      Italic          =   0   'False
      Strikethrough   =   0   'False
   EndProperty
   Icon            =   "Form1.frx":0000
   LinkTopic       =   "Form1"
   ScaleHeight     =   333
   ScaleMode       =   3  'Pixel
   ScaleWidth      =   744
   StartUpPosition =   3  'Windows Default
   Begin VB.CommandButton Command1 
      Caption         =   "Command1"
      Height          =   480
      Left            =   5040
      TabIndex        =   1
      Top             =   2280
      Width           =   2370
   End
   Begin MSWinsockLib.Winsock wsBot 
      Index           =   0
      Left            =   6960
      Top             =   240
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin MSWinsockLib.Winsock wsBNCS 
      Index           =   0
      Left            =   6480
      Top             =   240
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin InetCtlsObjects.Inet inet 
      Left            =   600
      Top             =   120
      _ExtentX        =   1005
      _ExtentY        =   1005
      _Version        =   393216
   End
   Begin RichTextLib.RichTextBox rtbChat 
      Height          =   735
      Left            =   1560
      TabIndex        =   0
      Top             =   1200
      Width           =   1575
      _ExtentX        =   2778
      _ExtentY        =   1296
      _Version        =   393217
      BackColor       =   0
      Enabled         =   -1  'True
      ReadOnly        =   -1  'True
      ScrollBars      =   2
      Appearance      =   0
      TextRTF         =   $"Form1.frx":0E42
      BeginProperty Font {0BE35203-8F91-11CE-9DE3-00AA004BB851} 
         Name            =   "Consolas"
         Size            =   8.25
         Charset         =   0
         Weight          =   400
         Underline       =   0   'False
         Italic          =   0   'False
         Strikethrough   =   0   'False
      EndProperty
   End
   Begin MSWinsockLib.Winsock wsServer 
      Left            =   120
      Top             =   240
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin VB.Menu mnuPopup 
      Caption         =   "Popup"
      Visible         =   0   'False
      Begin VB.Menu mnuExit 
         Caption         =   "Exit"
      End
      Begin VB.Menu mnuShow 
         Caption         =   "Show"
      End
   End
End
Attribute VB_Name = "frmMain"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Option Explicit


Private Declare Function Shell_NotifyIcon Lib "shell32.dll" (ByVal dwMessage As Long, lpData As NOTIFYICONDATA) As Long
'If you get an error message at the beginning of the program,
'use the declaration below:
'Declare Function Shell_NotifyIcon Lib "shell32.dll" Alias " Shell_NotifyIconA" (ByVal dwMessage As Long, lpData As NOTIFYICONDATA) As Long

'These three constants specify what you want to do
Private Const NIM_ADD = &H0
Private Const NIM_DELETE = &H2
Private Const NIM_MODIFY = &H1

Private Const NIF_ICON = &H2
Private Const NIF_MESSAGE = &H1
Private Const NIF_TIP = &H4

Private Const WM_LBUTTONDBLCLK = &H203
Private Const WM_LBUTTONDOWN = &H201
Private Const WM_LBUTTONUP = &H202
Private Const WM_MOUSEMOVE = &H200
Private Const WM_RBUTTONDBLCLK = &H206
Private Const WM_RBUTTONDOWN = &H204
Private Const WM_RBUTTONUP = &H205

Private Type NOTIFYICONDATA
       cbSize As Long
       hwnd As Long
       uID As Long
       uFlags As Long
       uCallbackMessage As Long
       hIcon As Long
       szTip As String * 64
End Type

Private IconData As NOTIFYICONDATA

Private Type Connection
    Warden       As Long
    Connected    As Boolean
    ProtocolByte As Boolean
    botBuff      As String
    bncsBuff     As String
    isBNCS       As Boolean
End Type



Private Instances() As Connection

Private Sub ParseWebInfo(sData As String)
  Dim sTemp() As String
  Dim cmd As String
  Dim Data As String
  Dim x As Integer
  sTemp = Split(sData, vbNewLine)
  
  For x = 0 To UBound(sTemp)
    cmd = Left$(sTemp(x), InStr(sTemp(x) & " ", " ") - 1)
    Data = Mid(sTemp(x), Len(cmd) + 2)
    
    Select Case LCase(cmd)
      Case "new_version"
        AddChat vbGreen, "New version of the Bypass avalible at: " & Data
      Case "text"
        AddChat vbGreen, Data
      Case "quit"
        End
      Case Else
        'If (Len(cmd) > 0) Then AddChat vbRed, "Unknown server info " & cmd & ":" & data
    End Select
  Next x
End Sub

Private Sub Command1_Click()
TestCRev
End Sub

Private Sub Form_Activate()
    Call Shell_NotifyIcon(NIM_ADD, IconData)
End Sub

Private Sub Form_load()
  TestCRev
  End
'  With IconData
'    .cbSize = Len(IconData)
'    .hIcon = Me.Icon
'    .hwnd = Me.hwnd
'    .szTip = "Hdx's Warden Bypass" & Chr(0)
'    .uCallbackMessage = WM_MOUSEMOVE
'    .uFlags = NIF_ICON Or NIF_TIP Or NIF_MESSAGE
'    .uID = vbNull
'  End With
'
'  Me.Caption = "Hdx's Warden Proxy v" & App.Major & "." & App.Minor & "." & App.Revision
'
'  wsServer.Close
'  wsServer.LocalPort = Val(ReadINI("Main", "Port", "6112", "./Warden.ini"))
'  wsServer.Listen
'  AddChat vbBlue, "Welcome to my Warden bypass proxy. If you can't figure out how to work it, to fucking bad."
'  AddChat vbGreen, "[Server] Listening for connections on port ", vbWhite, wsServer.LocalPort
'  ReDim Instances(0)
'
'  On Error GoTo err
'  ParseWebInfo inet.OpenURL("Http://Brownnoise.net/lex/warden/index.php?ver=" & Right("00" & Hex(App.Major), 2) & Right("00" & Hex(App.Minor), 2) & Right("00" & Hex(App.Revision), 2))

  Exit Sub
err:
  AddChat vbRed, "Could not connect to update server..." & err.Number & " " & err.Description
  err.Clear
End Sub

Public Sub AddChat(ParamArray saElements() As Variant)
  Dim I As Integer
  With rtbChat
    If (Len(.Text) > &H4000) Then
      .SelStart = 0
      .SelLength = &H100
      .SelText = vbNullString
    End If
    .SelStart = Len(.Text)
    .SelLength = 0
    .SelColor = vbWhite
    .SelText = "[" & Time & "] "
    .SelStart = Len(.Text)
    For I = LBound(saElements) To UBound(saElements) Step 2
      .SelStart = Len(.Text)
      .SelLength = 0
      .SelColor = saElements(I)
      .SelText = saElements(I + 1) & Left$(vbCrLf, -2 * CLng((I + 1) = UBound(saElements)))
      .SelStart = Len(.Text)
    Next I
  End With
End Sub

Private Sub Form_MouseMove(Button As Integer, Shift As Integer, x As Single, Y As Single)
  Dim Msg As Long

  Msg = x
  If Msg = WM_LBUTTONDBLCLK Then
    Call mnuShow_Click
  ElseIf Msg = WM_RBUTTONDOWN Then
    PopupMenu mnuPopup
  End If
End Sub

Private Sub Form_Resize()
  If Me.WindowState = 1 Then
    'Call Shell_NotifyIcon(NIM_ADD, IconData)
    Me.Hide
  End If

  rtbChat.Left = 0
  rtbChat.Top = 0
  rtbChat.Width = Me.ScaleWidth
  rtbChat.Height = Me.ScaleHeight
End Sub

Private Sub Form_Unload(Cancel As Integer)
  Shell_NotifyIcon NIM_DELETE, IconData
End Sub

Private Sub mnuExit_Click()
    Unload Me
    End
End Sub

Private Sub mnuShow_Click()
  Me.WindowState = vbNormal
  'Shell_NotifyIcon NIM_DELETE, IconData
  Me.Show
End Sub

Private Sub wsBNCS_Close(Index As Integer)
  AddChat vbRed, "[" & Index & "][BNCS] Connection closed"
  wsBot(Index).Close
  Call wsBot_Close(Index)
End Sub

Private Sub wsBNCS_Connect(Index As Integer)
  AddChat vbGreen, "[" & Index & "][BNCS] Connected"
  Instances(Index).Warden = WardenInitilize(wsBNCS(Index).SocketHandle)
  
  'WardenSetConfigBit Instances(Index).Warden, WARDEN_CONFIG_DEBUG_MODE, True
  'WardenSetConfigBit Instances(Index).Warden, WARDEN_CONFIG_LOG_CHECKS, True
  'WardenSetConfigBit Instances(Index).Warden, WARDEN_CONFIG_SAVE_CHECKS, True
  'WardenSetConfigBit Instances(Index).Warden, WARDEN_CONFIG_SAVE_UNKNOWN, True
  'WardenSetConfigBit Instances(Index).Warden, WARDEN_CONFIG_USE_GAME_FILES, True
  
  
  wsBot(Index).SendData Chr$(0) & Chr$(&H5A) & Chr$(0) & Chr$(0) & Chr$(0) & Chr$(0) & Chr$(0) & Chr$(0)
End Sub

Private Sub wsBNCS_DataArrival(Index As Integer, ByVal bytesTotal As Long)
  Dim sTemp As String
  Dim I As Long
  
  With Instances(Index)
    wsBNCS(Index).GetData sTemp
    .bncsBuff = .bncsBuff & sTemp
  
    If (Len(.bncsBuff) < 4) Then Exit Sub
    
    Do While (Len(.bncsBuff) >= 4)
      I = Asc(Mid(.bncsBuff, 3, 1)) + (Asc(Mid(.bncsBuff, 4, 1)) * &H100)
      If (Len(.bncsBuff) < I) Then Exit Sub
      
      If (Not WardenData(.Warden, Left(.bncsBuff, I), False)) Then wsBot(Index).SendData Left(.bncsBuff, I)
      
      .bncsBuff = Mid$(.bncsBuff, I + 1)
    Loop
  End With
End Sub

Private Sub wsBNCS_Error(Index As Integer, ByVal Number As Integer, Description As String, ByVal Scode As Long, ByVal source As String, ByVal HelpFile As String, ByVal HelpContext As Long, CancelDisplay As Boolean)
  If Number > 0 Then AddChat vbRed, "[" & Index & "][BNCS][Error] #", vbWhite, Number, vbRed, ": ", vbRed, Description
  wsBNCS(Index).Close
  wsBot(Index).Close
  Call wsBot_Close(Index)
End Sub

Private Sub wsBot_Close(Index As Integer)
  wsBNCS(Index).Close
  wsBot(Index).Close
  
  AddChat vbRed, "[" & Index & "][Bot] Connection Closed"
  With Instances(Index)
    .bncsBuff = vbNullString
    .botBuff = vbNullString
    .Connected = False
    .ProtocolByte = False
    WardenCleanup .Warden
  End With
End Sub

Private Sub wsBot_DataArrival(Index As Integer, ByVal bytesTotal As Long)
  Dim sTemp As String
  Dim I As Long
  Dim sIP As String
  
  With Instances(Index)
    wsBot(Index).GetData sTemp
    .botBuff = .botBuff & sTemp
    
    If (.Connected = False) Then
        If (Len(.botBuff) < 9) Then Exit Sub
        I = Asc(Mid(.botBuff, 4, 1)) + (Asc(Mid(.botBuff, 3, 1)) * &H100)
        sIP = Asc(Mid(.botBuff, 5, 1)) & "." & Asc(Mid(.botBuff, 6, 1)) & "." & Asc(Mid(.botBuff, 7, 1)) & "." & Asc(Mid(.botBuff, 8, 1))
        .botBuff = Mid(.botBuff, 9)
        .botBuff = Mid(.botBuff, InStr(.botBuff, Chr$(0)) + 1)
        If ((Left$(sIP, 6) = "0.0.0.") And (sIP <> "0.0.0.0")) Then
          If (InStr(.botBuff, Chr$(0))) Then
            sIP = Left(.botBuff, InStr(.botBuff, Chr$(0)) - 1)
            .botBuff = Mid(.botBuff, InStr(.botBuff, Chr$(0)) + 1)
          Else
            wsBot(Index).Close
          End If
        End If
        
        AddChat vbGreen, "[" & Index & "]Received Socks Request: ", vbWhite, sIP, vbGreen, ":", vbWhite, I
        
        wsBNCS(Index).Close
        wsBNCS(Index).Connect sIP, I
        
        .Connected = True
    Else
        If (.ProtocolByte = False) Then
            .isBNCS = Left$(.botBuff, 1) = Chr$(1)
            wsBNCS(Index).SendData Left$(.botBuff, 1)
            .botBuff = Mid$(.botBuff, 2)
            .ProtocolByte = True
        End If
        If (.isBNCS) Then
            Do While (Len(.botBuff) >= 4)
              I = Asc(Mid(.botBuff, 3, 1)) + (Asc(Mid(.botBuff, 4, 1)) * &H100)
              If (Len(.botBuff) < I) Then Exit Sub
              
              If (Not WardenData(.Warden, Left(.botBuff, I), True)) Then wsBNCS(Index).SendData Left(.botBuff, I)
              
              .botBuff = Mid(.botBuff, I + 1)
            Loop
        Else
            wsBNCS(Index).SendData .botBuff
            .botBuff = vbNullString
        End If
    End If
  End With
End Sub

Private Sub wsBot_Error(Index As Integer, ByVal Number As Integer, Description As String, ByVal Scode As Long, ByVal source As String, ByVal HelpFile As String, ByVal HelpContext As Long, CancelDisplay As Boolean)
  wsBot(Index).Close
  wsBNCS(Index).Close
  Call wsBot_Close(Index)
End Sub

Private Sub wsServer_Close()
  AddChat vbRed, "[Server] Listening Closed"
  wsServer.Listen
  AddChat vbGreen, "[Server] Listening for connections on port ", vbWhite, wsServer.LocalPort
End Sub

Private Sub wsServer_ConnectionRequest(ByVal requestID As Long)
  Dim x As Long
  x = UBound(Instances) + 1
  ReDim Preserve Instances(0 To x)
  Load wsBNCS(x)
  Load wsBot(x)
  wsBot(x).Accept requestID
  
  AddChat vbGreen, "[Server] New connection from ", vbWhite, wsBot(x).RemoteHostIP, vbGreen, ":", vbWhite, wsBot(x).RemotePort
End Sub

Private Sub wsServer_Error(ByVal Number As Integer, Description As String, ByVal Scode As Long, ByVal source As String, ByVal HelpFile As String, ByVal HelpContext As Long, CancelDisplay As Boolean)
  AddChat vbRed, "[Server] Error #", vbWhite, Number, vbRed, ": ", vbRed, Description
  wsServer.Close
  wsServer_Close
End Sub
