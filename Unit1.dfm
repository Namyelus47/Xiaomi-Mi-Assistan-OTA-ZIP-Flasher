object Form1: TForm1
  Left = 0
  Top = 0
  Caption = 'Xiaomi ADB Sideload Flash'
  ClientHeight = 510
  ClientWidth = 624
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  TextHeight = 15
  object lblStatus: TLabel
    Left = 8
    Top = 8
    Width = 32
    Height = 15
    Caption = 'Ready'
  end
  object Memo1: TMemo
    Left = 8
    Top = 28
    Width = 608
    Height = 305
    ScrollBars = ssVertical
    TabOrder = 0
  end
  object ProgressBar1: TProgressBar
    Left = 8
    Top = 340
    Width = 608
    Height = 22
    TabOrder = 1
  end
  object btnReadInfo: TButton
    Left = 8
    Top = 372
    Width = 608
    Height = 34
    Caption = 'Read Info'
    TabOrder = 2
    OnClick = btnReadInfoClick
  end
  object btnFlash: TButton
    Left = 8
    Top = 412
    Width = 608
    Height = 34
    Caption = 'Select Firmware and Start Flashing'
    TabOrder = 3
    OnClick = btnFlashClick
  end
  object btnFormatData: TButton
    Left = 8
    Top = 452
    Width = 608
    Height = 34
    Caption = 'Format Data (Wipe)'
    TabOrder = 4
    OnClick = btnFormatDataClick
  end
  object OpenDialog1: TOpenDialog
    Filter = 'ZIP files (*.zip)|*.zip|All files (*.*)|*.*'
    Title = 'Select File'
    Left = 296
    Top = 480
  end
end
