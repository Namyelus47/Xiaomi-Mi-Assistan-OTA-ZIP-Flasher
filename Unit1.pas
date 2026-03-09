unit Unit1;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.StdCtrls, Vcl.ComCtrls, DCPcrypt2, LibUSB, DCPrijndael, DCPmd5,
  System.IOUtils, IdHTTP, IdSSLOpenSSL, System.Hash,
  System.NetEncoding, System.JSON, IdURI, ShellAPI,
  System.AnsiStrings;

type
  TForm1 = class(TForm)
    Memo1: TMemo;
    btnReadInfo: TButton;
    btnFlash: TButton;
    btnFormatData: TButton;
    OpenDialog1: TOpenDialog;
    ProgressBar1: TProgressBar;
    lblStatus: TLabel;
    procedure btnReadInfoClick(Sender: TObject);
    procedure btnFlashClick(Sender: TObject);
    procedure btnFormatDataClick(Sender: TObject);
  private
    FBusy: Boolean;
    procedure SetBusy(ABusy: Boolean);
    procedure Log(const S: string);
    procedure SetStatus(const S: string);
    procedure SetProgress(APos: Integer; AMax: Integer = 100);
  public
  end;

const
  ADB_CLASS            = $FF;
  ADB_SUB_CLASS        = $42;
  ADB_PROTOCOL_CODE    = 1;
  ADB_CONNECT          = $4E584E43;
  ADB_VERSION          = $01000001;
  ADB_OPEN             = $4E45504F;
  ADB_OKAY             = $59414B4F;
  ADB_WRTE             = $45545257;
  ADB_CLSE             = $45534C43;
  ADB_MAX_DATA         = 1024 * 1024;
  CHUNK_SIZE           = 2048;
  ADB_SIDELOAD_CHUNK_SIZE = 1024 * 64;

type
  adb_usb_packet = packed record
    cmd:      UInt32;
    arg0:     UInt32;
    arg1:     UInt32;
    len:      UInt32;
    checksum: UInt32;
    magic:    UInt32;
  end;

var
  Form1: TForm1;

  ctx:           Plibusb_context;
  dev_handle:    Plibusb_device_handle;
  bulk_in:       Integer;
  bulk_out:      Integer;
  interface_num: Integer;

  codename:   PAnsiChar;
  version:    PAnsiChar;
  serial_num: PAnsiChar;
  codebase:   PAnsiChar;
  branch:     PAnsiChar;
  lang:       PAnsiChar;
  region:     PAnsiChar;
  romzone:    PAnsiChar;

implementation

{$R *.dfm}
{$R-}
{$Q-}

// ============================================================================
// Thread-safe UI helpers
// ============================================================================
procedure TForm1.Log(const S: string);
begin
  TThread.Queue(nil, procedure
  begin
    Memo1.Lines.Add(S);
  end);
end;

procedure TForm1.SetStatus(const S: string);
begin
  TThread.Queue(nil, procedure
  begin
    lblStatus.Caption := S;
  end);
end;

procedure TForm1.SetProgress(APos: Integer; AMax: Integer);
begin
  TThread.Queue(nil, procedure
  begin
    ProgressBar1.Max := AMax;
    ProgressBar1.Position := APos;
  end);
end;

procedure TForm1.SetBusy(ABusy: Boolean);
begin
  TThread.Queue(nil, procedure
  begin
    FBusy := ABusy;
    btnReadInfo.Enabled := not ABusy;
    btnFlash.Enabled := not ABusy;
    btnFormatData.Enabled := not ABusy;
    if not ABusy then
    begin
      lblStatus.Caption := 'Ready';
      ProgressBar1.Position := 0;
    end;
  end);
end;

// ============================================================================
// SetupAPI + WinUSB direct access (bypasses libusb on Windows)
// ============================================================================
const
  DIGCF_PRESENT         = $00000002;
  DIGCF_ALLCLASSES      = $00000004;
  DIGCF_DEVICEINTERFACE = $00000010;
  SPDRP_HARDWAREID      = $00000001;
  SPDRP_SERVICE         = $00000006;

type
  TSPDevInfoData = packed record
    cbSize: DWORD;
    ClassGuid: TGUID;
    DevInst: DWORD;
    Reserved: ULONG_PTR;
  end;

  TSPDevIntfData = packed record
    cbSize: DWORD;
    InterfaceClassGuid: TGUID;
    Flags: DWORD;
    Reserved: ULONG_PTR;
  end;

  TSPDevIntfDetailDataW = packed record
    cbSize: DWORD;
    DevicePath: array[0..0] of WideChar;
  end;
  PSPDevIntfDetailDataW = ^TSPDevIntfDetailDataW;

  TWinUsbPipeInfo = packed record
    PipeType: DWORD;
    PipeId: Byte;
    MaximumPacketSize: Word;
    Interval: Byte;
  end;

  TUSBInterfaceDescriptor = packed record
    bLength: Byte;
    bDescriptorType: Byte;
    bInterfaceNumber: Byte;
    bAlternateSetting: Byte;
    bNumEndpoints: Byte;
    bInterfaceClass: Byte;
    bInterfaceSubClass: Byte;
    bInterfaceProtocol: Byte;
    iInterface: Byte;
  end;

// --- SetupAPI imports ---
function SetupDiGetClassDevsW(ClassGuid: PGUID; Enumerator: PWideChar;
  hwndParent: HWND; Flags: DWORD): Pointer; stdcall; external 'setupapi.dll';
function SetupDiEnumDeviceInfo(DeviceInfoSet: Pointer; MemberIndex: DWORD;
  var DeviceInfoData: TSPDevInfoData): BOOL; stdcall; external 'setupapi.dll';
function SetupDiEnumDeviceInterfaces(DeviceInfoSet: Pointer;
  DeviceInfoData: Pointer; var InterfaceClassGuid: TGUID; MemberIndex: DWORD;
  var DeviceInterfaceData: TSPDevIntfData): BOOL; stdcall; external 'setupapi.dll';
function SetupDiGetDeviceInterfaceDetailW(DeviceInfoSet: Pointer;
  var DeviceInterfaceData: TSPDevIntfData;
  DeviceInterfaceDetailData: PSPDevIntfDetailDataW;
  DeviceInterfaceDetailDataSize: DWORD; var RequiredSize: DWORD;
  DeviceInfoData: Pointer): BOOL; stdcall; external 'setupapi.dll';
function SetupDiGetDeviceRegistryPropertyW(DeviceInfoSet: Pointer;
  var DeviceInfoData: TSPDevInfoData; Prop: DWORD; var PropertyRegDataType: DWORD;
  PropertyBuffer: PByte; PropertyBufferSize: DWORD;
  var RequiredSize: DWORD): BOOL; stdcall; external 'setupapi.dll';
function SetupDiDestroyDeviceInfoList(DeviceInfoSet: Pointer): BOOL;
  stdcall; external 'setupapi.dll';
function SetupDiOpenDevRegKey(DeviceInfoSet: Pointer;
  var DeviceInfoData: TSPDevInfoData; Scope: DWORD; HwProfile: DWORD;
  KeyType: DWORD; samDesired: DWORD): THandle;
  stdcall; external 'setupapi.dll' name 'SetupDiOpenDevRegKey';

// --- WinUSB imports (dynamic load) ---
type
  TWinUsb_Initialize = function(DeviceHandle: THandle;
    var InterfaceHandle: THandle): BOOL; stdcall;
  TWinUsb_Free = function(InterfaceHandle: THandle): BOOL; stdcall;
  TWinUsb_QueryInterfaceSettings = function(InterfaceHandle: THandle;
    AlternateInterfaceNumber: Byte;
    var UsbAltInterfaceDescriptor: TUSBInterfaceDescriptor): BOOL; stdcall;
  TWinUsb_QueryPipe = function(InterfaceHandle: THandle;
    AlternateInterfaceNumber: Byte; PipeIndex: Byte;
    var PipeInformation: TWinUsbPipeInfo): BOOL; stdcall;
  TWinUsb_ReadPipe = function(InterfaceHandle: THandle; PipeID: Byte;
    Buffer: Pointer; BufferLength: DWORD; var LengthTransferred: DWORD;
    Overlapped: Pointer): BOOL; stdcall;
  TWinUsb_WritePipe = function(InterfaceHandle: THandle; PipeID: Byte;
    Buffer: Pointer; BufferLength: DWORD; var LengthTransferred: DWORD;
    Overlapped: Pointer): BOOL; stdcall;
  TWinUsb_SetPipePolicy = function(InterfaceHandle: THandle; PipeID: Byte;
    PolicyType: DWORD; ValueLength: DWORD; Value: Pointer): BOOL; stdcall;

var
  WinUsb_Initialize: TWinUsb_Initialize = nil;
  WinUsb_Free: TWinUsb_Free = nil;
  WinUsb_QueryInterfaceSettings: TWinUsb_QueryInterfaceSettings = nil;
  WinUsb_QueryPipe: TWinUsb_QueryPipe = nil;
  WinUsb_ReadPipe: TWinUsb_ReadPipe = nil;
  WinUsb_WritePipe: TWinUsb_WritePipe = nil;
  WinUsb_SetPipePolicy: TWinUsb_SetPipePolicy = nil;
  hWinUsbDll: THandle = 0;
  g_WinUsbHandle: THandle = INVALID_HANDLE_VALUE;
  g_DeviceFileHandle: THandle = INVALID_HANDLE_VALUE;
  g_UseWinUSB: Boolean = False;

function LoadWinUSBDll: Boolean;
begin
  if hWinUsbDll <> 0 then begin Result := True; Exit; end;
  hWinUsbDll := LoadLibrary('winusb.dll');
  if hWinUsbDll = 0 then begin Result := False; Exit; end;
  @WinUsb_Initialize := GetProcAddress(hWinUsbDll, 'WinUsb_Initialize');
  @WinUsb_Free := GetProcAddress(hWinUsbDll, 'WinUsb_Free');
  @WinUsb_QueryInterfaceSettings := GetProcAddress(hWinUsbDll, 'WinUsb_QueryInterfaceSettings');
  @WinUsb_QueryPipe := GetProcAddress(hWinUsbDll, 'WinUsb_QueryPipe');
  @WinUsb_ReadPipe := GetProcAddress(hWinUsbDll, 'WinUsb_ReadPipe');
  @WinUsb_WritePipe := GetProcAddress(hWinUsbDll, 'WinUsb_WritePipe');
  @WinUsb_SetPipePolicy := GetProcAddress(hWinUsbDll, 'WinUsb_SetPipePolicy');
  Result := Assigned(WinUsb_Initialize) and Assigned(WinUsb_Free) and
            Assigned(WinUsb_ReadPipe) and Assigned(WinUsb_WritePipe);
end;

// Find device path via SetupAPI device interfaces
function FindDevicePathByGUID(var IntfGuid: TGUID; const VidPid: string;
  out DevPath: string): Boolean;
var
  hDevInfo: Pointer;
  intfData: TSPDevIntfData;
  detailBuf: array[0..1023] of Byte;
  pDetail: PSPDevIntfDetailDataW;
  reqSize: DWORD;
  idx: Integer;
  path: string;
begin
  Result := False;
  DevPath := '';
  hDevInfo := SetupDiGetClassDevsW(@IntfGuid, nil, 0,
    DIGCF_PRESENT or DIGCF_DEVICEINTERFACE);
  if NativeUInt(hDevInfo) = NativeUInt(INVALID_HANDLE_VALUE) then Exit;
  try
    idx := 0;
    intfData.cbSize := SizeOf(TSPDevIntfData);
    while SetupDiEnumDeviceInterfaces(hDevInfo, nil, IntfGuid, idx, intfData) do
    begin
      reqSize := 0;
      pDetail := @detailBuf[0];
      pDetail.cbSize := 4 + 2;
      if SizeOf(Pointer) = 8 then pDetail.cbSize := 8;
      if SetupDiGetDeviceInterfaceDetailW(hDevInfo, intfData, pDetail,
        SizeOf(detailBuf), reqSize, nil) then
      begin
        path := UpperCase(PWideChar(@pDetail.DevicePath));
        if Pos(UpperCase(VidPid), path) > 0 then
        begin
          DevPath := PWideChar(@pDetail.DevicePath);
          Result := True;
          Exit;
        end;
      end;
      Inc(idx);
    end;
  finally
    SetupDiDestroyDeviceInfoList(hDevInfo);
  end;
end;

// Find Xiaomi device path via registry GUIDs, class GUID, or generic GUIDs
function FindXiaomiDevicePath(out DevPath: string): Boolean;
const
  GUID_DEVINTERFACE_USB_DEVICE: TGUID = '{A5DCBF10-6530-11D2-901F-00C04FB951ED}';
  GUID_DEVINTERFACE_WINUSB:     TGUID = '{DEE824EF-729B-4A0E-9C14-B7117D33A817}';
  DICS_FLAG_GLOBAL = 1;
  DIREG_DEV = 1;
  KEY_READ_VAL = $20019;
var
  hDevInfo: Pointer;
  devInfoData: TSPDevInfoData;
  intfData: TSPDevIntfData;
  detailBuf: array[0..1023] of Byte;
  pDetail: PSPDevIntfDetailDataW;
  hwIdBuf: array[0..1023] of WideChar;
  guidBuf: array[0..511] of WideChar;
  regType, reqSize, bufSize: DWORD;
  hwIdStr, guidStr: string;
  i, j: Integer;
  tryGuid: TGUID;
  hKey: THandle;
begin
  Result := False;
  DevPath := '';

  // Step 1: Find device via SetupAPI and read its DeviceInterfaceGUIDs
  hDevInfo := SetupDiGetClassDevsW(nil, PWideChar('USB'), 0,
    DIGCF_PRESENT or DIGCF_ALLCLASSES);
  if NativeUInt(hDevInfo) = NativeUInt(INVALID_HANDLE_VALUE) then Exit;
  try
    i := 0;
    devInfoData.cbSize := SizeOf(TSPDevInfoData);
    while SetupDiEnumDeviceInfo(hDevInfo, i, devInfoData) do
    begin
      FillChar(hwIdBuf, SizeOf(hwIdBuf), 0);
      reqSize := 0;
      regType := 0;
      SetupDiGetDeviceRegistryPropertyW(hDevInfo, devInfoData, SPDRP_HARDWAREID,
        regType, @hwIdBuf[0], SizeOf(hwIdBuf), reqSize);
      hwIdStr := UpperCase(hwIdBuf);

      if (Pos('VID_18D1', hwIdStr) > 0) or (Pos('VID_2717', hwIdStr) > 0) then
      begin
        // Read DeviceInterfaceGUIDs from device registry key
        hKey := SetupDiOpenDevRegKey(hDevInfo, devInfoData,
          DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ_VAL);
        if (hKey <> 0) and (hKey <> INVALID_HANDLE_VALUE) then
        begin
          FillChar(guidBuf, SizeOf(guidBuf), 0);
          bufSize := SizeOf(guidBuf);
          regType := 0;
          if RegQueryValueExW(hKey, 'DeviceInterfaceGUIDs', nil, @regType,
            @guidBuf[0], @bufSize) = 0 then
          begin
            guidStr := guidBuf;
            try
              tryGuid := StringToGUID(guidStr);
              if FindDevicePathByGUID(tryGuid, 'VID_18D1', DevPath) then
              begin
                RegCloseKey(hKey);
                Result := True;
                Exit;
              end;
            except
            end;
          end;
          RegCloseKey(hKey);
        end;

        // Try the device's own ClassGuid
        tryGuid := devInfoData.ClassGuid;
        if FindDevicePathByGUID(tryGuid, 'VID_18D1', DevPath) then
        begin
          Result := True;
          Exit;
        end;

        // Try enumerating interfaces directly on this device
        j := 0;
        intfData.cbSize := SizeOf(TSPDevIntfData);
        while SetupDiEnumDeviceInterfaces(hDevInfo, @devInfoData,
          devInfoData.ClassGuid, j, intfData) do
        begin
          pDetail := @detailBuf[0];
          pDetail.cbSize := 4 + 2;
          if SizeOf(Pointer) = 8 then pDetail.cbSize := 8;
          if SetupDiGetDeviceInterfaceDetailW(hDevInfo, intfData, pDetail,
            SizeOf(detailBuf), reqSize, nil) then
          begin
            DevPath := PWideChar(@pDetail.DevicePath);
            Result := True;
            Exit;
          end;
          Inc(j);
        end;
      end;
      Inc(i);
    end;
  finally
    SetupDiDestroyDeviceInfoList(hDevInfo);
  end;

  // Step 2: Fallback - try generic GUIDs
  tryGuid := GUID_DEVINTERFACE_WINUSB;
  if FindDevicePathByGUID(tryGuid, 'VID_18D1&PID_4E11', DevPath) then
  begin
    Result := True;
    Exit;
  end;

  tryGuid := GUID_DEVINTERFACE_USB_DEVICE;
  if FindDevicePathByGUID(tryGuid, 'VID_18D1&PID_4E11', DevPath) then
  begin
    Result := True;
    Exit;
  end;
end;

// ============================================================================
// Auto-install WinUSB driver via .inf + pnputil (runs as admin)
// ============================================================================
function CreateWinUSBInf(out InfPath: string): Boolean;
const
  INF_CONTENT =
    '[Version]'#13#10 +
    'Signature   = "$Windows NT$"'#13#10 +
    'Class       = USBDevice'#13#10 +
    'ClassGUID   = {88BAE032-5A81-49f0-BC3D-A4FF138216D6}'#13#10 +
    'Provider    = %ManufacturerName%'#13#10 +
    'DriverVer   = 01/01/2024,1.0.0.0'#13#10 +
    ''#13#10 +
    '[Manufacturer]'#13#10 +
    '%ManufacturerName% = Standard,NTamd64,NTx86'#13#10 +
    ''#13#10 +
    '[Standard.NTamd64]'#13#10 +
    '%DeviceName% = USB_Install, USB\VID_18D1&PID_4E11'#13#10 +
    '%DeviceName% = USB_Install, USB\VID_18D1&PID_D001'#13#10 +
    '%DeviceName% = USB_Install, USB\VID_2717&PID_4E11'#13#10 +
    '%DeviceName% = USB_Install, USB\VID_2717&PID_4EE0'#13#10 +
    ''#13#10 +
    '[Standard.NTx86]'#13#10 +
    '%DeviceName% = USB_Install, USB\VID_18D1&PID_4E11'#13#10 +
    '%DeviceName% = USB_Install, USB\VID_18D1&PID_D001'#13#10 +
    '%DeviceName% = USB_Install, USB\VID_2717&PID_4E11'#13#10 +
    '%DeviceName% = USB_Install, USB\VID_2717&PID_4EE0'#13#10 +
    ''#13#10 +
    '[USB_Install]'#13#10 +
    'Include = winusb.inf'#13#10 +
    'Needs   = WINUSB.NT'#13#10 +
    ''#13#10 +
    '[USB_Install.Services]'#13#10 +
    'Include = winusb.inf'#13#10 +
    'Needs   = WINUSB.NT.Services'#13#10 +
    ''#13#10 +
    '[USB_Install.HW]'#13#10 +
    'AddReg = Dev_AddReg'#13#10 +
    ''#13#10 +
    '[Dev_AddReg]'#13#10 +
    'HKR,,DeviceInterfaceGUIDs,0x10000,"{DEE824EF-729B-4A0E-9C14-B7117D33A817}"'#13#10 +
    ''#13#10 +
    '[Strings]'#13#10 +
    'ManufacturerName = "Xiaomi"'#13#10 +
    'DeviceName       = "Xiaomi ADB Sideload"'#13#10;
var
  F: TFileStream;
  Data: TBytes;
begin
  Result := False;
  InfPath := ExtractFilePath(Application.ExeName) + 'xiaomi_winusb.inf';
  try
    Data := TEncoding.ANSI.GetBytes(INF_CONTENT);
    F := TFileStream.Create(InfPath, fmCreate);
    try
      F.WriteBuffer(Data[0], Length(Data));
    finally
      F.Free;
    end;
    Result := True;
  except
  end;
end;

function TryAutoInstallWinUSBDriver: Boolean;
var
  InfPath, Params: string;
  SEI: TShellExecuteInfo;
  ExitCode: DWORD;
begin
  Result := False;

  // Step 1: Look for zadig.exe in app folder
  if FileExists(ExtractFilePath(Application.ExeName) + 'zadig.exe') then
  begin
    Form1.Log('Found zadig.exe, launching...');
    ShellExecute(0, 'runas', PChar(ExtractFilePath(Application.ExeName) + 'zadig.exe'),
      nil, PChar(ExtractFilePath(Application.ExeName)), SW_SHOWNORMAL);
    Form1.Log('Install WinUSB driver in Zadig, then retry.');
    Exit;
  end;

  // Step 2: Create .inf and try pnputil (admin)
  if not CreateWinUSBInf(InfPath) then
  begin
    Form1.Log('Could not create driver .inf file');
    Exit;
  end;

  Form1.Log('Installing WinUSB driver (admin required)...');
  Params := '/add-driver "' + InfPath + '" /install';

  FillChar(SEI, SizeOf(SEI), 0);
  SEI.cbSize := SizeOf(SEI);
  SEI.fMask := $00000040; // SEE_MASK_NOCLOSEPROCESS
  SEI.lpVerb := 'runas';
  SEI.lpFile := 'pnputil.exe';
  SEI.lpParameters := PChar(Params);
  SEI.nShow := SW_HIDE;

  if not ShellExecuteExW(@SEI) then
  begin
    Form1.Log('Driver install cancelled or failed');
    Form1.Log('Please install WinUSB driver manually using Zadig');
    ShellExecute(0, 'open', 'https://zadig.akeo.ie/', nil, nil, SW_SHOWNORMAL);
    Exit;
  end;

  // Wait for pnputil to finish
  if SEI.hProcess <> 0 then
  begin
    WaitForSingleObject(SEI.hProcess, 30000);
    GetExitCodeProcess(SEI.hProcess, ExitCode);
    CloseHandle(SEI.hProcess);
    if ExitCode = 0 then
    begin
      Form1.Log('Driver installed successfully!');
      Form1.Log('Retrying connection...');
      Sleep(2000); // Wait for driver to settle
      Result := True;
    end
    else
    begin
      Form1.Log('pnputil returned error ' + IntToStr(ExitCode));
      Form1.Log('Please install WinUSB driver manually using Zadig');
      ShellExecute(0, 'open', 'https://zadig.akeo.ie/', nil, nil, SW_SHOWNORMAL);
    end;
  end;
end;

// Open device via WinUSB and find bulk endpoints
function TryWinUSBDirect: Integer;
var
  devPath: string;
  intfDesc: TUSBInterfaceDescriptor;
  pipeInfo: TWinUsbPipeInfo;
  pipeIdx: Byte;
  timeout: DWORD;
  attempt: Integer;
begin
  Result := 1;
  g_UseWinUSB := False;

  if not LoadWinUSBDll then
  begin
    Form1.Log('WinUSB driver not available');
    Exit;
  end;

  Form1.Log('Searching for device...');

  for attempt := 1 to 2 do
  begin
    if not FindXiaomiDevicePath(devPath) then
    begin
      Form1.Log('Device not found via WinUSB');
      Exit;
    end;

    // Open device file
    g_DeviceFileHandle := CreateFileW(PWideChar(devPath),
      GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ or FILE_SHARE_WRITE,
      nil, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, 0);
    if g_DeviceFileHandle = INVALID_HANDLE_VALUE then
      g_DeviceFileHandle := CreateFileW(PWideChar(devPath),
        GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ or FILE_SHARE_WRITE,
        nil, OPEN_EXISTING, 0, 0);
    if g_DeviceFileHandle = INVALID_HANDLE_VALUE then
    begin
      Form1.Log('Cannot open device (error ' + IntToStr(GetLastError) + ')');
      Exit;
    end;

    // Initialize WinUSB
    if WinUsb_Initialize(g_DeviceFileHandle, g_WinUsbHandle) then
      Break; // Success, continue to endpoint setup

    Form1.Log('WinUSB init failed (error ' + IntToStr(GetLastError) + ')');
    CloseHandle(g_DeviceFileHandle);
    g_DeviceFileHandle := INVALID_HANDLE_VALUE;

    // Try auto-install driver on first attempt only
    if attempt = 1 then
    begin
      Form1.Log('Attempting to install WinUSB driver...');
      if not TryAutoInstallWinUSBDriver then
        Exit;
      // Loop will retry
    end
    else
      Exit;
  end;

  // Query interface settings
  if not WinUsb_QueryInterfaceSettings(g_WinUsbHandle, 0, intfDesc) then
  begin
    WinUsb_Free(g_WinUsbHandle);
    CloseHandle(g_DeviceFileHandle);
    Exit;
  end;

  // Find bulk IN and OUT endpoints
  bulk_in := -1;
  bulk_out := -1;
  interface_num := intfDesc.bInterfaceNumber;
  for pipeIdx := 0 to intfDesc.bNumEndpoints - 1 do
  begin
    if WinUsb_QueryPipe(g_WinUsbHandle, 0, pipeIdx, pipeInfo) then
    begin
      if pipeInfo.PipeType = 2 then // Bulk
      begin
        if (pipeInfo.PipeId and $80) <> 0 then
        begin
          if bulk_in = -1 then bulk_in := pipeInfo.PipeId;
        end
        else
        begin
          if bulk_out = -1 then bulk_out := pipeInfo.PipeId;
        end;
      end;
    end;
  end;

  if (bulk_in = -1) or (bulk_out = -1) then
  begin
    Form1.Log('No bulk endpoints found');
    WinUsb_Free(g_WinUsbHandle);
    CloseHandle(g_DeviceFileHandle);
    Exit;
  end;

  // Set pipe timeout
  timeout := 1000;
  WinUsb_SetPipePolicy(g_WinUsbHandle, Byte(bulk_in), 3, SizeOf(timeout), @timeout);
  WinUsb_SetPipePolicy(g_WinUsbHandle, Byte(bulk_out), 3, SizeOf(timeout), @timeout);

  g_UseWinUSB := True;
  Form1.Log('Device connected via WinUSB');
  Result := 0;
end;

procedure CleanupWinUSB;
begin
  if g_WinUsbHandle <> INVALID_HANDLE_VALUE then
  begin
    if Assigned(WinUsb_Free) then WinUsb_Free(g_WinUsbHandle);
    g_WinUsbHandle := INVALID_HANDLE_VALUE;
  end;
  if g_DeviceFileHandle <> INVALID_HANDLE_VALUE then
  begin
    CloseHandle(g_DeviceFileHandle);
    g_DeviceFileHandle := INVALID_HANDLE_VALUE;
  end;
  g_UseWinUSB := False;
end;

// ============================================================================
// endpoint_is_output
// ============================================================================
function endpoint_is_output(endpoint: Byte): Boolean;
begin
  Result := (endpoint and LIBUSB_ENDPOINT_DIR_MASK) = LIBUSB_ENDPOINT_OUT;
end;

// ============================================================================
// check_device
// ============================================================================
function check_device(dev: Plibusb_device): Integer;
type
  TIntfArray = array[0..255] of libusb_interface;
  PIntfArray = ^TIntfArray;
  TEpArray = array[0..255] of libusb_endpoint_descriptor;
  PEpArray = ^TEpArray;
var
  desc: libusb_device_descriptor;
  configs: Plibusb_config_descriptor;
  r, i, endpoint_idx: Integer;
  intfArr: PIntfArray;
  intf_desc: Plibusb_interface_descriptor;
  epArr: PEpArray;
  endpoint_addr, endpoint_attr, transfer_type: Byte;
begin
  Result := 1;

  r := libusb_get_device_descriptor(dev, @desc);
  if r <> LIBUSB_SUCCESS then Exit;

  configs := nil;
  r := libusb_get_active_config_descriptor(dev, @configs);
  if (r <> LIBUSB_SUCCESS) or (configs = nil) then Exit;

  bulk_in := -1;
  bulk_out := -1;
  interface_num := -1;

  if configs.bNumInterfaces = 0 then Exit;

  intfArr := PIntfArray(configs.theinterface);
  for i := 0 to configs.bNumInterfaces - 1 do
  begin
    if intfArr^[i].num_altsetting = 0 then Continue;
    interface_num := i;
    intf_desc := intfArr^[i].altsetting;

    if not ((intf_desc.bInterfaceClass = ADB_CLASS) and
            (intf_desc.bInterfaceSubClass = ADB_SUB_CLASS) and
            (intf_desc.bInterfaceProtocol = ADB_PROTOCOL_CODE)) then
      Continue;
    if intfArr^[i].num_altsetting <> 1 then Continue;
    if intf_desc.bNumEndpoints = 0 then Continue;

    epArr := PEpArray(intf_desc.endpoint);
    for endpoint_idx := 0 to intf_desc.bNumEndpoints - 1 do
    begin
      endpoint_addr := epArr^[endpoint_idx].bEndpointAddress;
      endpoint_attr := epArr^[endpoint_idx].bmAttributes;
      transfer_type := endpoint_attr and LIBUSB_TRANSFER_TYPE_MASK;
      if transfer_type <> LIBUSB_TRANSFER_TYPE_BULK then Continue;

      if endpoint_is_output(endpoint_addr) and (bulk_out = -1) then
        bulk_out := endpoint_addr
      else if (not endpoint_is_output(endpoint_addr)) and (bulk_in = -1) then
        bulk_in := endpoint_addr;

      if (bulk_out <> -1) and (bulk_in <> -1) then
      begin
        Result := 0;
        Exit;
      end;
    end;
  end;
end;

// ============================================================================
// scan_for_device - tries WinUSB direct, then libusb backends
// ============================================================================
const
  XIAOMI_VIDS: array[0..1] of Word = ($18D1, $2717);
  XIAOMI_PIDS: array[0..3] of Word = ($D001, $4E11, $4EE0, $4EE2);

function TryScanWithBackend(const BackendName: string; UseUsbDk: Boolean): Integer;
var
  devs: PPlibusb_device;
  dev_list: ^Plibusb_device_array;
  dev: Plibusb_device;
  cnt: Integer;
  i, r, v, p: Integer;
  found: Boolean;
begin
  Result := 1;

  r := libusb_init(@ctx);
  if r <> LIBUSB_SUCCESS then Exit;

  if UseUsbDk then
  begin
    if not libusb_set_option_available then
    begin
      libusb_exit(ctx);
      ctx := nil;
      Exit;
    end;
    try
      r := libusb_set_option(ctx, LIBUSB_OPTION_USE_USBDK);
    except
      libusb_exit(ctx);
      ctx := nil;
      Exit;
    end;
    if r <> LIBUSB_SUCCESS then
    begin
      libusb_exit(ctx);
      ctx := nil;
      Exit;
    end;
  end;

  // Method 1: Try libusb_get_device_list
  devs := nil;
  cnt := libusb_get_device_list(ctx, @devs);
  if cnt > 0 then
  begin
    dev_list := Pointer(devs);
    found := False;
    for i := 0 to cnt - 1 do
    begin
      dev := dev_list^[i];
      if dev = nil then Break;
      if check_device(dev) = 0 then
      begin
        found := True;
        r := libusb_open(dev, @dev_handle);
        if r <> LIBUSB_SUCCESS then
        begin
          libusb_free_device_list(devs, 1);
          Exit;
        end;
        r := libusb_claim_interface(dev_handle, interface_num);
        if r <> LIBUSB_SUCCESS then
        begin
          libusb_free_device_list(devs, 1);
          Exit;
        end;
        Break;
      end;
    end;
    libusb_free_device_list(devs, 1);
    if found then begin Result := 0; Exit; end;
  end
  else
  begin
    if devs <> nil then libusb_free_device_list(devs, 1);
  end;

  // Method 2: Try known VID:PID pairs directly
  for v := Low(XIAOMI_VIDS) to High(XIAOMI_VIDS) do
  begin
    for p := Low(XIAOMI_PIDS) to High(XIAOMI_PIDS) do
    begin
      dev_handle := libusb_open_device_with_vid_pid(ctx, XIAOMI_VIDS[v], XIAOMI_PIDS[p]);
      if dev_handle <> nil then
      begin
        dev := libusb_get_device(dev_handle);
        if (dev <> nil) and (check_device(dev) = 0) then
        begin
          r := libusb_claim_interface(dev_handle, interface_num);
          if r <> LIBUSB_SUCCESS then
          begin
            libusb_close(dev_handle);
            dev_handle := nil;
            Continue;
          end;
          Result := 0;
          Exit;
        end
        else
        begin
          bulk_in := $81;
          bulk_out := $01;
          interface_num := 0;
          r := libusb_claim_interface(dev_handle, interface_num);
          if r <> LIBUSB_SUCCESS then
          begin
            libusb_close(dev_handle);
            dev_handle := nil;
            Continue;
          end;
          Result := 0;
          Exit;
        end;
      end;
    end;
  end;

  libusb_exit(ctx);
  ctx := nil;
end;

function scan_for_device: Integer;
begin
  // Try 1: WinUSB direct access
  Result := TryWinUSBDirect;
  if Result = 0 then Exit;

  // Try 2: libusb with UsbDk backend
  Result := TryScanWithBackend('UsbDk', True);
  if Result = 0 then Exit;

  // Try 3: libusb default backend
  Result := TryScanWithBackend('Default', False);
end;

// ============================================================================
// usb_read / usb_write - dual mode (WinUSB or libusb)
// ============================================================================
function usb_read(data: Pointer; datalen: Integer): Integer;
var
  read_len_long: LongInt;
  read_len_dw: DWORD;
  r: Integer;
begin
  if g_UseWinUSB then
  begin
    read_len_dw := 0;
    if WinUsb_ReadPipe(g_WinUsbHandle, Byte(bulk_in), data, DWORD(datalen),
       read_len_dw, nil) then
      Result := Integer(read_len_dw)
    else
      Result := -1;
  end
  else
  begin
    read_len_long := 0;
    r := libusb_bulk_transfer(dev_handle, Byte(bulk_in), PChar(data),
         datalen, @read_len_long, DWORD(1000));
    if r <> LIBUSB_SUCCESS then
      Result := -1
    else
      Result := read_len_long;
  end;
end;

function usb_write(data: Pointer; datalen: Integer): Integer;
var
  write_len_long: LongInt;
  write_len_dw: DWORD;
  r: Integer;
begin
  if g_UseWinUSB then
  begin
    write_len_dw := 0;
    if WinUsb_WritePipe(g_WinUsbHandle, Byte(bulk_out), data, DWORD(datalen),
       write_len_dw, nil) then
      Result := Integer(write_len_dw)
    else
      Result := -1;
  end
  else
  begin
    write_len_long := 0;
    r := libusb_bulk_transfer(dev_handle, Byte(bulk_out), PChar(data),
         datalen, @write_len_long, DWORD(1000));
    if r <> LIBUSB_SUCCESS then
      Result := -1
    else
      Result := write_len_long;
  end;
end;

// ============================================================================
// send_command
// ============================================================================
function send_command(cmd, arg0, arg1: UInt32; data: Pointer; datalen: Integer): Integer;
var
  pkt: adb_usb_packet;
begin
  pkt.cmd      := cmd;
  pkt.arg0     := arg0;
  pkt.arg1     := arg1;
  pkt.len      := datalen;
  pkt.checksum := 0;
  pkt.magic    := cmd xor $FFFFFFFF;

  if usb_write(@pkt, SizeOf(pkt)) = -1 then begin Result := 1; Exit; end;
  if (datalen > 0) and (usb_write(data, datalen) = -1) then begin Result := 1; Exit; end;
  Result := 0;
end;

// ============================================================================
// recv_packet
// ============================================================================
function recv_packet(var pkt: adb_usb_packet; data: Pointer; var data_len: Integer): Integer;
begin
  if usb_read(@pkt, SizeOf(adb_usb_packet)) = 0 then begin Result := 1; Exit; end;
  if (pkt.len > 0) and (usb_read(data, pkt.len) = 0) then begin Result := 1; Exit; end;
  data_len := pkt.len;
  Result := 0;
end;

// ============================================================================
// send_recovery_commands
// ============================================================================
function send_recovery_commands(const command: PAnsiChar; response: PAnsiChar): Integer;
var
  cmd_len: Integer;
  cmd: array of AnsiChar;
  pkt: adb_usb_packet;
  data: array[0..511] of AnsiChar;
  data_len: Integer;
begin
  cmd_len := System.AnsiStrings.StrLen(command);
  SetLength(cmd, cmd_len + 2);
  Move(command^, cmd[0], cmd_len);
  Inc(cmd_len);
  cmd[cmd_len] := #0;

  if send_command(ADB_OPEN, 1, 0, @cmd[0], cmd_len) <> 0 then begin Result := 1; Exit; end;

  recv_packet(pkt, @data[0], data_len); // OKAY
  if recv_packet(pkt, response, data_len) <> 0 then begin Result := 1; Exit; end;

  response[data_len] := #0;
  if (data_len > 0) and (response[data_len - 1] = #10) then
    response[data_len - 1] := #0;

  recv_packet(pkt, @data[0], data_len); // CLSE
  Result := 0;
end;

// ============================================================================
// connect_device_read_info
// ============================================================================
function connect_device_read_info(read_info: Boolean): Integer;
var
  buf: array[0..511] of AnsiChar;
  buf_len: Integer;
  pkt: adb_usb_packet;
  try_count: Integer;
begin
  if send_command(ADB_CONNECT, ADB_VERSION, ADB_MAX_DATA, PAnsiChar('host::'#0), 7) <> 0 then
  begin Result := 1; Exit; end;

  try_count := 10;
  while try_count > 0 do
  begin
    if recv_packet(pkt, @buf[0], buf_len) <> 0 then begin Result := 1; Exit; end;
    if pkt.cmd = ADB_CONNECT then Break;
    Dec(try_count);
  end;
  if try_count = 0 then begin Result := 1; Exit; end;

  buf[buf_len] := #0;
  if not CompareMem(@buf[0], PAnsiChar('sideload::'), 10) then begin Result := 1; Exit; end;
  if not read_info then begin Result := 0; Exit; end;

  if send_recovery_commands('getdevice:', codename) <> 0 then begin Result := 1; Exit; end;
  if send_recovery_commands('getversion:', version) <> 0 then begin Result := 1; Exit; end;
  if send_recovery_commands('getsn:', serial_num) <> 0 then begin Result := 1; Exit; end;
  if send_recovery_commands('getcodebase:', codebase) <> 0 then begin Result := 1; Exit; end;
  if send_recovery_commands('getbranch:', branch) <> 0 then begin Result := 1; Exit; end;
  if send_recovery_commands('getlanguage:', lang) <> 0 then begin Result := 1; Exit; end;
  if send_recovery_commands('getregion:', region) <> 0 then begin Result := 1; Exit; end;
  if send_recovery_commands('getromzone:', romzone) <> 0 then begin Result := 1; Exit; end;
  Result := 0;
end;

// ============================================================================
// generate_md5_hash (with progress callback)
// ============================================================================
function generate_md5_hash(const filename: string): AnsiString;
const
  BUF_SIZE = 1024 * 1024; // 1MB chunks
var
  Hash: TDCP_MD5;
  FS: TFileStream;
  digest: array[0..15] of Byte;
  buf: PByte;
  bytesRead: Integer;
  i: Integer;
  total, done: Int64;
  pct, old_pct: Integer;
begin
  Result := '';
  Hash := TDCP_MD5.Create(nil);
  try
    FS := TFileStream.Create(filename, fmOpenRead or fmShareDenyWrite);
    GetMem(buf, BUF_SIZE);
    try
      total := FS.Size;
      done := 0;
      old_pct := -1;
      Hash.Init;
      repeat
        bytesRead := FS.Read(buf^, BUF_SIZE);
        if bytesRead > 0 then
        begin
          Hash.Update(buf^, bytesRead);
          Inc(done, bytesRead);
          pct := Integer((done * 100) div total);
          if pct <> old_pct then
          begin
            Form1.SetProgress(pct);
            Form1.SetStatus(Format('Hashing... %d%%', [pct]));
            old_pct := pct;
          end;
        end;
      until bytesRead = 0;
      Hash.Final(digest);
    finally
      FreeMem(buf);
      FS.Free;
    end;
    for i := 0 to 15 do
      Result := Result + AnsiString(LowerCase(IntToHex(digest[i], 2)));
  finally
    Hash.Free;
  end;
end;

// ============================================================================
// URL-encode matching curl_easy_escape behavior (RFC 3986 unreserved only)
// ============================================================================
function CurlEscape(const S: AnsiString): AnsiString;
var
  i: Integer;
begin
  Result := '';
  for i := 1 to Length(S) do
  begin
    if S[i] in ['A'..'Z','a'..'z','0'..'9','-','_','.','~'] then
      Result := Result + S[i]
    else
      Result := Result + AnsiString(Format('%%%2.2X', [Ord(S[i])]));
  end;
end;

// ============================================================================
// AES-128-CBC encrypt (manual CBC using ECB, matches C tiny-aes)
// ============================================================================
procedure AES_CBC_Encrypt(const Key; const IV; var Data; DataLen: Integer);
var
  Cipher: TDCP_rijndael;
  iv_copy: array[0..15] of Byte;
  p, i: Integer;
  DataBytes: PByteArray;
begin
  Move(IV, iv_copy, 16);
  DataBytes := @Data;
  Cipher := TDCP_rijndael.Create(nil);
  try
    Cipher.Init(Key, 128, nil);
    p := 0;
    while p < DataLen do
    begin
      for i := 0 to 15 do
        DataBytes[p + i] := DataBytes[p + i] xor iv_copy[i];
      Cipher.EncryptECB(DataBytes[p], DataBytes[p]);
      Move(DataBytes[p], iv_copy[0], 16);
      Inc(p, 16);
    end;
  finally
    Cipher.Free;
  end;
end;

// ============================================================================
// AES-128-CBC decrypt (manual CBC using ECB, matches C tiny-aes)
// ============================================================================
procedure AES_CBC_Decrypt(const Key; const IV; var Data; DataLen: Integer);
var
  Cipher: TDCP_rijndael;
  iv_copy, next_iv: array[0..15] of Byte;
  p, i: Integer;
  DataBytes: PByteArray;
begin
  Move(IV, iv_copy, 16);
  DataBytes := @Data;
  Cipher := TDCP_rijndael.Create(nil);
  try
    Cipher.Init(Key, 128, nil);
    p := 0;
    while p < DataLen do
    begin
      Move(DataBytes[p], next_iv, 16);
      Cipher.DecryptECB(DataBytes[p], DataBytes[p]);
      for i := 0 to 15 do
        DataBytes[p + i] := DataBytes[p + i] xor iv_copy[i];
      Move(next_iv, iv_copy[0], 16);
      Inc(p, 16);
    end;
  finally
    Cipher.Free;
  end;
end;

// ============================================================================
// generate_firmware_sign
// ============================================================================
function generate_firmware_sign(const signfile: string): Integer;
const
  key: array[0..15] of Byte = ($6D, $69, $75, $69, $6F, $74, $61, $76,
                                $61, $6C, $69, $64, $65, $64, $31, $31);
  iv:  array[0..15] of Byte = ($30, $31, $30, $32, $30, $33, $30, $34,
                                $30, $35, $30, $36, $30, $37, $30, $38);
var
  json_request_str: AnsiString;
  json_request: array[0..1023] of AnsiChar;
  pkg_hash: AnsiString;
  len, mod_len, i: Integer;
  out_buf, json_post_data: AnsiString;
  encBytes, Decoded: TBytes;
  HTTP: TIdHTTP;
  SSL: TIdSSLIOHandlerSocketOpenSSL;
  Response, PostStream: TStringStream;
  RespJSON, PkgRom, CodeObj: TJSONValue;
  validate_str, decrypted_str: string;
  fp: TFileStream;
  code_val: Integer;
  code_msg, cur_rom_name, cur_rom_ver: string;
begin
  Result := 1;

  // Step 1: Hash firmware file
  Form1.Log('Hashing firmware file...');
  Form1.SetStatus('Hashing firmware...');
  pkg_hash := generate_md5_hash(signfile);
  Form1.Log('MD5: ' + String(pkg_hash));

  // Step 2: Build JSON request (matches C sprintf format exactly)
  FillChar(json_request, SizeOf(json_request), 0);
  json_request_str := AnsiString(Format(
    '{'#10#9'"d" : "%s",'#10#9'"v" : "%s",'#10#9'"c" : "%s",'#10#9 +
    '"b" : "%s",'#10#9'"sn" : "%s",'#10#9'"r" : "GL",'#10#9 +
    '"l" : "en-US",'#10#9'"f" : "1",'#10#9'"id" : "",'#10#9 +
    '"options" : {'#10#9#9'"zone" : %s'#10#9'},'#10#9'"pkg" : "%s"'#10'}',
    [String(AnsiString(codename)), String(AnsiString(version)),
     String(AnsiString(codebase)), String(AnsiString(branch)),
     String(AnsiString(serial_num)), String(AnsiString(romzone)),
     String(pkg_hash)]));
  Move(json_request_str[1], json_request[0], Length(json_request_str));
  len := System.AnsiStrings.StrLen(json_request);

  // PKCS7 padding
  mod_len := 16 - (len mod 16);
  if mod_len > 0 then
  begin
    for i := 0 to mod_len - 1 do
      json_request[len + i] := AnsiChar(mod_len);
    len := len + mod_len;
  end;

  // Step 3: Encrypt + encode
  Form1.Log('Encrypting request...');
  Form1.SetStatus('Encrypting...');
  Form1.SetProgress(0);
  AES_CBC_Encrypt(key, iv, json_request, len);

  SetLength(encBytes, len);
  Move(json_request[0], encBytes[0], len);
  out_buf := AnsiString(TNetEncoding.Base64.EncodeBytesToString(encBytes));
  out_buf := AnsiString(StringReplace(String(out_buf), #13#10, '', [rfReplaceAll]));
  out_buf := AnsiString(StringReplace(String(out_buf), #10, '', [rfReplaceAll]));
  json_post_data := CurlEscape(out_buf);

  // Step 4: Send to Xiaomi update server
  Form1.Log('Contacting update server...');
  Form1.SetStatus('Contacting server...');
  Form1.SetProgress(50);
  HTTP := TIdHTTP.Create(nil);
  SSL := TIdSSLIOHandlerSocketOpenSSL.Create(nil);
  Response := TStringStream.Create('', TEncoding.UTF8);
  PostStream := nil;
  try
    HTTP.IOHandler := SSL;
    HTTP.HandleRedirects := True;
    HTTP.Request.ContentType := 'application/x-www-form-urlencoded';
    HTTP.Request.UserAgent := 'MiTunes_UserAgent_v3.0';
    HTTP.Request.CustomHeaders.AddValue('clientId', 'MITUNES');
    HTTP.Request.CustomHeaders.AddValue('Connection', 'Keep-Alive');
    HTTP.Request.CustomHeaders.AddValue('Accept-Encoding', 'identity');

    PostStream := TStringStream.Create(
      Format('q=%s&t=&s=1', [String(json_post_data)]), TEncoding.ASCII);

    try
      HTTP.Post('http://update.miui.com/updates/miotaV3.php', PostStream, Response);
    except
      on E: EIdHTTPProtocolException do
      begin
        Form1.Log('Server returned error ' + IntToStr(E.ErrorCode) + ': ' + E.Message);
        Exit;
      end;
      on E: Exception do
      begin
        Form1.Log('Connection failed: ' + E.Message);
        Exit;
      end;
    end;

    if HTTP.ResponseCode <> 200 then
    begin
      Form1.Log('Server returned HTTP ' + IntToStr(HTTP.ResponseCode));
      Exit;
    end;
    Form1.Log('Server responded OK');
    Form1.SetProgress(75);

    // Step 5: Decrypt response
    Form1.Log('Decrypting response...');
    Form1.SetStatus('Decrypting response...');
    json_post_data := AnsiString(TIdURI.URLDecode(Response.DataString));
    Decoded := TNetEncoding.Base64.DecodeStringToBytes(String(json_post_data));
    AES_CBC_Decrypt(key, iv, Decoded[0], Length(Decoded));

    // Unpad PKCS7
    if Length(Decoded) > 0 then
      SetLength(Decoded, Length(Decoded) - Decoded[High(Decoded)]);

    decrypted_str := TEncoding.UTF8.GetString(Decoded);

    // Step 6: Parse JSON response
    RespJSON := TJSONObject.ParseJSONValue(decrypted_str);
    if RespJSON = nil then
    begin
      Form1.Log('Failed to parse server response');
      Exit;
    end;

    try
      // Check for error code
      CodeObj := (RespJSON as TJSONObject).Values['Code'];
      if (CodeObj <> nil) and (CodeObj is TJSONObject) then
      begin
        code_val := StrToIntDef((CodeObj as TJSONObject).Values['code'].Value, 0);
        code_msg := (CodeObj as TJSONObject).Values['message'].Value;
        if code_val <> 0 then
          Form1.Log('Server code ' + IntToStr(code_val) + ': ' + code_msg);
      end;

      // Show current ROM info if available
      if (RespJSON as TJSONObject).Values['CurrentRom'] <> nil then
      begin
        cur_rom_name := '';
        cur_rom_ver := '';
        try
          cur_rom_name := ((RespJSON as TJSONObject).Values['CurrentRom'] as TJSONObject).Values['device'].Value;
          cur_rom_ver := ((RespJSON as TJSONObject).Values['CurrentRom'] as TJSONObject).Values['version'].Value;
        except end;
        if cur_rom_name <> '' then
          Form1.Log('Current ROM: ' + cur_rom_name + ' ' + cur_rom_ver);
      end;

      // Get PkgRom with Validate key
      PkgRom := (RespJSON as TJSONObject).Values['PkgRom'];
      if PkgRom = nil then
      begin
        Form1.Log('');
        Form1.Log('Server did not authorize this firmware.');
        Form1.Log('Make sure the firmware file matches your device region.');
        Exit;
      end;

      if not (PkgRom is TJSONObject) then
      begin
        Form1.Log('Unexpected PkgRom format in response');
        Exit;
      end;

      validate_str := (PkgRom as TJSONObject).Values['Validate'].Value;
      if validate_str = '' then
      begin
        Form1.Log('Validate key is empty');
        Exit;
      end;

      // Write validate.key
      fp := TFileStream.Create('validate.key', fmCreate);
      try
        fp.WriteBuffer(PAnsiChar(AnsiString(validate_str))^, Length(validate_str));
      finally
        fp.Free;
      end;

      Form1.SetProgress(100);
      Form1.Log('Sign generated successfully');
      Form1.Log('Saved to: validate.key (' + IntToStr(Length(validate_str)) + ' bytes)');
      Result := 0;
    finally
      RespJSON.Free;
    end;

  finally
    PostStream.Free;
    Response.Free;
    SSL.Free;
    HTTP.Free;
  end;
end;

// ============================================================================
// start_sideload
// ============================================================================
function start_sideload(const sideload_file: string): Integer;
var
  fp_validate, fp: TFileStream;
  validate_file_size: Int64;
  validate: TBytes;
  file_size: Int64;
  sideload_host_command: AnsiString;
  work_buffer: PByte;
  dummy_data: array[0..63] of AnsiChar;
  dummy_data_size: Integer;
  pkt: adb_usb_packet;
  percentage, old_percentage: Int64;
  block, offset: Int64;
  to_write: Integer;
  block_str: AnsiString;
begin
  Result := 0;

  // Read validate.key
  fp_validate := TFileStream.Create('validate.key', fmOpenRead);
  try
    validate_file_size := fp_validate.Size;
    SetLength(validate, validate_file_size);
    fp_validate.ReadBuffer(validate[0], validate_file_size);
  finally
    fp_validate.Free;
  end;

  // Open sideload file
  fp := TFileStream.Create(sideload_file, fmOpenRead or fmShareDenyWrite);
  try
    file_size := fp.Size;

    sideload_host_command := AnsiString(Format('sideload-host:%d:%d:%s:0',
      [file_size, ADB_SIDELOAD_CHUNK_SIZE, TEncoding.ANSI.GetString(validate)]));
    send_command(ADB_OPEN, 1, 0, PAnsiChar(sideload_host_command),
                 Length(sideload_host_command) + 1);

    GetMem(work_buffer, ADB_SIDELOAD_CHUNK_SIZE);
    try
      percentage := 0;
      old_percentage := -1;
      Form1.SetProgress(0);

      while True do
      begin
        pkt.cmd := 0;
        recv_packet(pkt, @dummy_data[0], dummy_data_size);

        if pkt.cmd = ADB_OKAY then
          send_command(ADB_OKAY, pkt.arg1, pkt.arg0, nil, 0);
        if pkt.cmd <> ADB_WRTE then Continue;

        dummy_data[dummy_data_size] := #0;
        if dummy_data_size > 8 then
        begin
          Form1.Log(String(PAnsiChar(@dummy_data[0])));
          Break;
        end;

        block_str := Copy(AnsiString(PAnsiChar(@dummy_data[0])), 1, dummy_data_size);
        block := StrToInt64Def(String(block_str), 0);
        offset := block * ADB_SIDELOAD_CHUNK_SIZE;
        if offset > file_size then Break;

        to_write := ADB_SIDELOAD_CHUNK_SIZE;
        if offset + ADB_SIDELOAD_CHUNK_SIZE > file_size then
          to_write := file_size - offset;

        fp.Seek(offset, soBeginning);
        fp.ReadBuffer(work_buffer^, to_write);

        send_command(ADB_WRTE, pkt.arg1, pkt.arg0, work_buffer, to_write);
        send_command(ADB_OKAY, pkt.arg1, pkt.arg0, nil, 0);

        percentage := (offset * 100) div file_size;
        if percentage <> old_percentage then
        begin
          Form1.SetProgress(Integer(percentage));
          Form1.SetStatus(Format('Flashing... %d%%', [percentage]));
          old_percentage := percentage;
        end;
      end;

      Form1.SetProgress(100);
      Form1.SetStatus('Flashing complete');

    finally
      FreeMem(work_buffer);
    end;

  finally
    fp.Free;
  end;
end;

// ============================================================================
// Helpers
// ============================================================================
function ConnectAndReadInfo(readinfo: Boolean): Boolean;
begin
  Result := False;
  dev_handle := nil;

  if scan_for_device <> 0 then
  begin
    Form1.Log('No device found');
    Exit;
  end;

  GetMem(codename,   64);
  GetMem(version,    64);
  GetMem(serial_num, 64);
  GetMem(codebase,   64);
  GetMem(branch,     64);
  GetMem(lang,       64);
  GetMem(region,     64);
  GetMem(romzone,    64);

  if connect_device_read_info(readinfo) <> 0 then
  begin
    Form1.Log('Failed to connect with device');
    Exit;
  end;

  if readinfo then
    Form1.Log(Format(
      'Codename: %s'#13#10'Version: %s'#13#10'Serial: %s'#13#10 +
      'Codebase: %s'#13#10'Branch: %s'#13#10'Language: %s'#13#10 +
      'Region: %s'#13#10'Romzone: %s',
      [String(AnsiString(codename)), String(AnsiString(version)),
       String(AnsiString(serial_num)), String(AnsiString(codebase)),
       String(AnsiString(branch)), String(AnsiString(lang)),
       String(AnsiString(region)), String(AnsiString(romzone))]));

  Result := True;
end;

procedure FreeDeviceBuffers;
begin
  if codename <> nil then begin FreeMem(codename); codename := nil; end;
  if version <> nil then begin FreeMem(version); version := nil; end;
  if serial_num <> nil then begin FreeMem(serial_num); serial_num := nil; end;
  if codebase <> nil then begin FreeMem(codebase); codebase := nil; end;
  if branch <> nil then begin FreeMem(branch); branch := nil; end;
  if lang <> nil then begin FreeMem(lang); lang := nil; end;
  if region <> nil then begin FreeMem(region); region := nil; end;
  if romzone <> nil then begin FreeMem(romzone); romzone := nil; end;
end;

procedure CleanupUSB;
begin
  CleanupWinUSB;
  if dev_handle <> nil then
  begin
    libusb_release_interface(dev_handle, interface_num);
    libusb_close(dev_handle);
    dev_handle := nil;
  end;
  if ctx <> nil then
  begin
    libusb_exit(ctx);
    ctx := nil;
  end;
end;

// ============================================================================
// Button handlers (threaded)
// ============================================================================
procedure TForm1.btnReadInfoClick(Sender: TObject);
begin
  if FBusy then Exit;
  SetBusy(True);
  Memo1.Lines.Clear;
  Memo1.Lines.Add('Reading device info...');
  lblStatus.Caption := 'Reading info...';

  TThread.CreateAnonymousThread(procedure
  begin
    try
      if ConnectAndReadInfo(True) then
        Form1.Log('Device info read successfully!')
      else
        Form1.Log('Could not connect to device.');
    finally
      FreeDeviceBuffers;
      CleanupUSB;
      Form1.SetBusy(False);
    end;
  end).Start;
end;

procedure TForm1.btnFlashClick(Sender: TObject);
var
  FileName: string;
begin
  if FBusy then Exit;

  OpenDialog1.Title := 'Select Firmware File';
  OpenDialog1.Filter := 'ZIP files (*.zip)|*.zip|All files (*.*)|*.*';
  if not OpenDialog1.Execute then Exit;
  FileName := OpenDialog1.FileName;

  SetBusy(True);
  Memo1.Lines.Clear;
  Memo1.Lines.Add('Selected firmware: ' + FileName);
  Memo1.Lines.Add('Connecting to device...');
  lblStatus.Caption := 'Connecting...';

  TThread.CreateAnonymousThread(procedure
  begin
    try
      // Step 1: Connect and read device info
      if not ConnectAndReadInfo(True) then
      begin
        Form1.Log('Cannot flash without device connection.');
        Exit;
      end;

      // Step 2: Generate firmware sign
      Form1.Log('Generating firmware sign...');
      if generate_firmware_sign(FileName) <> 0 then
      begin
        Form1.Log('Failed to generate sign.');
        Exit;
      end;

      // Disconnect after sign generation
      FreeDeviceBuffers;
      CleanupUSB;

      // Step 3: Reconnect for flashing
      Form1.Log('');
      Form1.Log('Reconnecting for flashing...');
      Form1.SetStatus('Reconnecting...');
      Form1.SetProgress(0);
      if not ConnectAndReadInfo(False) then
      begin
        Form1.Log('Cannot reconnect to device for flashing.');
        Exit;
      end;

      // Step 4: Flash firmware
      Form1.Log('Flashing...');
      start_sideload(FileName);
      Form1.Log('Flashing complete!');
    finally
      FreeDeviceBuffers;
      CleanupUSB;
      Form1.SetBusy(False);
    end;
  end).Start;
end;

procedure TForm1.btnFormatDataClick(Sender: TObject);
begin
  if FBusy then Exit;

  if MessageDlg('WARNING: This will erase all user data! Continue?',
     mtWarning, [mbYes, mbNo], 0) <> mrYes then
    Exit;

  SetBusy(True);
  Memo1.Lines.Clear;
  Memo1.Lines.Add('Connecting to device...');
  lblStatus.Caption := 'Connecting...';

  TThread.CreateAnonymousThread(procedure
  var
    buf: array[0..255] of AnsiChar;
  begin
    try
      if not ConnectAndReadInfo(True) then
      begin
        Form1.Log('Cannot format without device connection.');
        Exit;
      end;

      Form1.Log('');
      Form1.Log('Formatting device...');
      Form1.SetStatus('Formatting...');
      send_recovery_commands('format-data:', @buf[0]);
      Form1.Log('Device formatted successfully');

      send_recovery_commands('reboot:', @buf[0]);
      Form1.Log('Reboot command sent.');
    finally
      FreeDeviceBuffers;
      CleanupUSB;
      Form1.SetBusy(False);
    end;
  end).Start;
end;

end.
