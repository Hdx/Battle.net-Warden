Attribute VB_Name = "modBlah"
Option Explicit

Private Declare Function GetPrivateProfileStringA Lib "kernel32" (ByVal lpApplicationName As String, ByVal lpKeyName As String, ByVal lpDefault As String, ByVal lpReturnedString As String, ByVal nSize As Long, ByVal lpFileName As String) As Long
Private Declare Function WritePrivateProfileStringA Lib "kernel32" (ByVal lpApplicationName As String, ByVal lpKeyName As String, ByVal lpString As Any, ByVal lpFileName As String) As Long

Public Function ReadINI(ByVal riSection As String, ByVal riKey As String, ByVal riDefault As String, ByVal riFile As String) As String
Dim sRiBuffer As String
Dim sRiValue  As String
Dim sRiLong   As Long
Dim INIFile   As String
  If InStr(riFile, ":\") = 0 Then
    INIFile = App.Path & "\" & riFile
  Else
    INIFile = riFile
  End If
  If LenB(Dir$(INIFile)) > 0 Then
    sRiBuffer = String$(255, vbNullChar)
    sRiLong = GetPrivateProfileStringA(riSection, riKey, vbNullChar, sRiBuffer, 255, INIFile)
    If Not Left$(sRiBuffer, 1) = vbNullChar Then
      sRiValue = Left$(sRiBuffer, sRiLong)
      If LenB(sRiValue) > 0 Then
        ReadINI = sRiValue
      Else
        ReadINI = riDefault
      End If
    Else
      ReadINI = riDefault
    End If
  Else
    ReadINI = riDefault
  End If
End Function

Public Sub WriteINI(ByVal wiSection As String, ByVal wiKey As String, ByVal wiValue As String, ByVal wiFile As String)
Dim INIFile As String
  If InStr(wiFile, ":\") = 0 Then
    INIFile = App.Path & "\" & wiFile
  Else
    INIFile = wiFile
  End If
  WritePrivateProfileStringA wiSection, wiKey, wiValue, INIFile
End Sub


Public Function DebugOutput(ByVal sIn As String) As String
   Dim x1 As Long, y1 As Long
   Dim iLen As Long, iPos As Long
   Dim sB As String, sT As String
   Dim sOut As String
   Dim Offset As Long, sOffset As String
      
   iLen = Len(sIn)
   If iLen = 0 Then Exit Function
   sOut = ""
   Offset = 0
   For x1 = 0 To ((iLen - 1) \ 16)
       sOffset = Right$("0000" & Hex(Offset), 4)
       sB = String(48, " ")
       sT = "................"
       For y1 = 1 To 16
           iPos = 16 * x1 + y1
           If iPos > iLen Then Exit For
           Mid(sB, 3 * (y1 - 1) + 1, 2) = Right("00" & Hex(Asc(Mid(sIn, iPos, 1))), 2) & " "
           Select Case Asc(Mid(sIn, iPos, 1))
           Case 0, 9, 10, 11, 12, 13
           Case Else
               Mid(sT, y1, 1) = Mid(sIn, iPos, 1)
           End Select
       Next y1
       If Len(sOut) > 0 Then sOut = sOut & vbCrLf
       sOut = sOut & sOffset & ":  "
       sOut = sOut & sB & "  " & sT
       Offset = Offset + 16
   Next x1
   DebugOutput = sOut
End Function

'======================================================================================================
Public Function StringFormat(source As String, ParamArray params() As Variant)
On Error GoTo ERROR_HANDLER:
    Dim retVal As String, I As Integer
    retVal = source
    For I = LBound(params) To UBound(params)
        retVal = Replace(retVal, "{" & I & "}", CStr(params(I)))
    Next
    StringFormat = retVal
    Exit Function
ERROR_HANDLER:
End Function
Public Function HexToStr(ByVal HexStr As String) As String
Dim Temp As String, I As Long
  HexStr = Replace$(HexStr, Space$(1), vbNullString)
  Temp = Space$(Len(HexStr) \ 2)
  For I = 1 To Len(HexStr) \ 2
    Mid$(Temp, I, 1) = Chr$(Val("&H" & Mid$(HexStr, I * 2 - 1, 2)))
  Next I
  HexToStr = Temp
End Function

Public Function StrToHex(ByVal sData As String, Optional ByVal NoSpaces As Boolean = False) As String
    Dim sRet As String
    Dim I As Integer
    
    For I = 1 To Len(sData)
        sRet = StringFormat("{0}{1}{2}", sRet, IIf(NoSpaces Or I = 1, vbNullString, Space$(1)), ZeroOffset(Asc(Mid(sData, I, 1)), 2))
    Next I
        
    StrToHex = sRet
End Function
Public Function ZeroOffset(lData As Long, iLen As Integer) As String
    ZeroOffset = Right$(String$(iLen, "0") & Hex(lData), iLen)
End Function
'======================================================================================================


