Imports Microsoft
Imports Microsoft.Win32
Imports Microsoft.Win32.Registry
Imports System.Management
Imports System.Diagnostics
Imports System.ComponentModel 
Imports System.Text

Module Module1

    Sub Main(ByVal Args() As String)
        'Esta aplicación puede tener o no argumentos para correr la aplicación en modo silencioso o solo listar los objetos. 


        If Args.Length = 0 Then
            'Sólo listará los objetos encontrados sin eliminarlos. 
            Detect_Kill_Processes()
            If Analize_Sub_Keys("SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Nothing) = True Then
                Console.WriteLine("HKLM\" & "SOFTWARE\Microsoft\Windows\CurrentVersion\Run\  Cuenta con un registro comprometido!!")
            End If
            If Analize_Sub_Keys("SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Nothing) = True Then
                Console.WriteLine("HKLM\" & "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\  Cuenta con un registro comprometido!!")
            End If
            Evaluate_Key_Branch("SYSTEM\ControlSet001\Services")
            Evaluate_Key_Branch("SYSTEM\ControlSet002\Services")
            Evaluate_Key_Branch("SYSTEM\CurrentControlSet\Services")
        End If
    End Sub

    Private Sub Detect_Kill_Processes()
        'Esta rutina detecta si existe un proceso de PowerShell con los parámetros de Silencioso, lo que indicaría un potencial malware
        Dim Proc As Process

        For Each Proc In Process.GetProcesses
            If InStr(1, "powershell", Proc.ProcessName, CompareMethod.Text) > 0 Then
                If InStr(1, "hidden", GetCommandLine(Proc)) Then
                    'Si dentro de la linea de comandos se toma el parámetro Hidden, es muy probable encontrar el comando del malware, por lo que se registra el proceso
                    Console.WriteLine("Se encontró el proceso powershell con el PID " & Proc.Id & " ejecutándose con el parámetro de oculto")
                End If
            End If

        Next
    End Sub

    Private Function GetCommandLine(ByVal P As Process) As String
        Dim CommandLine As New StringBuilder(P.MainModule.FileName)

        CommandLine.Append(" ")
        Dim Searcher As New ManagementObjectSearcher("SELECT CommandLine FROM Win32_Process WHERE ProcessId = " & P.Id)
        Dim Objt As ManagementObject

        For Each Objt In Searcher.Get()
            CommandLine.Append(Objt("CommandLine").ToString)
            CommandLine.Append(" ")
        Next

        Return CommandLine.ToString
    End Function

    Private Function Evaluate_Key_Branch(ByVal KeyBranchName As String) As Boolean
        'Esta función analizará dentro de una rama de Llaves la existencia de un valor determinado. 
        'KeyBranchName: La rama del registro a ser analizada (Sólo evaluará el primer nivel) 
        Dim RegBranch As RegistryKey
        Dim SubKey As String
        Dim RegValue As String

        Try
            RegBranch = My.Computer.Registry.LocalMachine.OpenSubKey(KeyBranchName)
            For Each SubKey In RegBranch.GetSubKeyNames()
                'Hace loop por cada llave de registro en la rama principal 
                RegValue = Nothing
                If Analize_Sub_Keys(KeyBranchName & "\" & SubKey, "ImagePath", RegValue) = True Then
                    'Si alguna de las subllaves analizadas devuelve verdadero (encontró coincidencia), entonces imprime en pantalla el hallazgo
                    Console.WriteLine("HKLM\" & KeyBranchName & "\" & SubKey & ",ImagePath," & RegValue)
                End If
            Next

        Catch ex As Exception
            Console.WriteLine("La rama de registro " & KeyBranchName & " no se pudo leer o no existe")
            Return False
        End Try
    End Function

    Private Function Analize_Sub_Keys(ByVal KeyBranchName As String, Optional ByVal ExplicitKeyName As String = "", Optional ByVal RValue As String = "") As Boolean
        'Esta función analizará una o varios valores de registro para determinar si contienen el valor a encontrar para nuestro proposito
        'KeyBranchName:  La rama de registros en donde se analizará la información. 
        'ExplicitKeyName:  Se limitará a buscar un sólo valor ubicado dentro de la rama del primer parámetro. 
        Dim RegistryValue As String
        Dim Subkey As RegistryKey
        Dim RegValueName As String

        Try
            Subkey = My.Computer.Registry.LocalMachine.OpenSubKey(KeyBranchName)
            If Not ExplicitKeyName Is Nothing Then
                RegistryValue = Subkey.GetValue(ExplicitKeyName, Nothing).ToString
                If Not RegistryValue Is Nothing Then
                    If InStr(1, "powershell", RegistryValue, CompareMethod.Text) > 0 Then
                        'Si encontró alguna coincidencia en el registro analizado que contenga el parámetro "powershell" entonces devolverá verdadero.
                        'De otra forma, devolverá falso. 
                        RValue = RegistryValue
                        Return True
                    End If
                    Return False
                End If
            Else
                For Each RegValueName In Subkey.GetValueNames
                    RegistryValue = Subkey.GetValue(RegValueName, Nothing).ToString
                    If Not RegistryValue Is Nothing Then
                        If InStr(1, "powershell", RegistryValue, CompareMethod.Text) > 0 Then
                            'Si encontró alguna coincidencia en el registro analizado que contenga el parámetro "powershell" entonces devolverá verdadero.
                            'De otra forma, devolverá falso. 
                            RValue = RegistryValue
                            Return True
                        End If
                    End If
                Next
                Return False
            End If



        Catch ex As Exception
            Console.WriteLine("El valor de registro " & KeyBranchName & "\" & ExplicitKeyName & " no se pudo leer o no existe.")
            Return False
        End Try
        Return False
    End Function

End Module



